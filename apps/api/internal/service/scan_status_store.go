package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
)

// Shared scan-status store (M72): the ScanTracker's state in Redis, so that a
// scan started on one API process is readable from another, and survives a
// restart of either.
//
// # Model
//
// Per SBOM, ONE key, scanstatus1:{<sbom>}, a hash holding the published
// status, the group's distinct failures, the active runs (r:<gen> -> lease
// expiry) and the tombstones of runs swept as interrupted (l:<gen>); see
// scanStatusLua. One key is evicted all or nothing (Codex M72 R11 High-1).
// It expires after the tracker's retention (scan deadline + 15m, at least
// 1h), refreshed on every write.
//
// A run holds a LEASE (ScanStatusLease, 90s) that the process running it
// renews every ScanStatusHeartbeat (30s). A run whose lease ran out — the
// process died, was restarted, or could not reach Redis for longer than the
// lease — is swept by the next access and recorded as failed with reason
// "interrupted"; once no run of the SBOM is active the SBOM reads failed
// (interrupted). If the run was in fact alive (Redis was unreachable from its
// process), its next heartbeat revives it, and its own outcome replaces the
// "interrupted" one when it finishes. Lease times are Redis's clock (TIME), so
// clock skew between API processes does not matter.
//
// Overlapping runs of one SBOM form a group exactly as in the in-memory
// tracker (M62): running until every run of the group has ended, then failed
// if any failed (markers joined, reasons merged), completed otherwise. A Begin
// when no run is active starts a new group.
//
// # Tenant isolation
//
// The keys are per SBOM id (a random UUID). They hold only the generic
// markers and reason codes scan-status returns (F445: never a raw error), and
// scan-status reads them only after the SBOM was found in the caller's
// project by the RLS-scoped query (GetVulnerabilitiesBySbom, a 404 for any
// other tenant's SBOM), the same gate the in-memory tracker relied on.
//
// # Failure
//
// Every call is bounded by scanStatusOpTimeout and goes through the client's
// circuit breaker. The tracker treats every error as "shared state unknown":
// the scan itself never waits on, or fails because of, this store.

const (
	scanStatusPrefix = "scanstatus1:"
	// ScanStatusLease is how long a run stays active without a heartbeat.
	ScanStatusLease = 90 * time.Second
	// ScanStatusHeartbeat is how often a process renews its runs' leases
	// (and retries writes that failed).
	ScanStatusHeartbeat = 30 * time.Second
	// scanStatusOpTimeout bounds one store round trip.
	scanStatusOpTimeout = 1 * time.Second
	// scanStatusMaxLost bounds the ids of interrupted runs kept for a late
	// revival or outcome.
	scanStatusMaxLost = 64
	// ScanReasonInterrupted: the process running the scan stopped (or lost
	// Redis for longer than the lease) before the scan reported an outcome.
	ScanReasonInterrupted = "interrupted"
)

// scanInterruptedMarker is the error string of an interrupted run.
var scanInterruptedMarker = ScanFailureMarker("scan", []string{ScanReasonInterrupted})

// scanStatusKeys is the SBOM's one status key (as KEYS for the scripts).
func scanStatusKeys(sbomID uuid.UUID) []string {
	return []string{scanStatusPrefix + "{" + sbomID.String() + "}"}
}

// scanStatusLua is shared by every script. KEYS[1] is the SBOM's ONE key, a
// hash (Codex M72 R11 High-1: one key is evicted all or nothing, so the
// state, the active runs and the interruptions can never be split):
//
//	state, error, reasons, updated   the published status
//	outcomes      JSON: the group's distinct failures (marker + reasons),
//	              bounded by the marker vocabulary (Codex M72 R2 High-3)
//	r:<gen>       an active run, value = lease expiry (ms, Redis time)
//	l:<gen>       a run swept as interrupted (a tombstone), value = sweep time;
//	              at most MAX_LOST (Codex M72 R3 Medium-2), they survive a new
//	              group and expire after MAX_RUN_AGE (Codex M72 R10 High-1)
//	lost_dropped  when a tombstone was dropped (or the runs were found lost)
const scanStatusLua = `
local K = KEYS[1]
local function nowms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local function fields()
  local all = redis.call('HGETALL', K)
  local runs, lost = {}, {}
  for i = 1, #all, 2 do
    local f, v = all[i], all[i + 1]
    local p = string.sub(f, 1, 2)
    if p == 'r:' then
      runs[string.sub(f, 3)] = tonumber(v) or 0
    elseif p == 'l:' then
      lost[string.sub(f, 3)] = tonumber(v) or 0
    end
  end
  return runs, lost
end
local function count(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end
local function active_count()
  local runs = fields()
  return count(runs)
end
local function load_outcomes()
  local raw = redis.call('HGET', K, 'outcomes')
  if not raw then return {} end
  local ok, v = pcall(cjson.decode, raw)
  if ok and type(v) == 'table' then return v end
  return {}
end
local function save_outcomes(o)
  if #o == 0 then
    redis.call('HSET', K, 'outcomes', '[]')
  else
    redis.call('HSET', K, 'outcomes', cjson.encode(o))
  end
end
local function add_failure(msg, rs)
  if msg == '' then return end
  local o = load_outcomes()
  for _, e in ipairs(o) do
    if e.m == msg then
      if type(e.r) ~= 'table' then e.r = {} end
      local have = {}
      for _, r in ipairs(e.r) do have[r] = true end
      for _, r in ipairs(rs) do
        if not have[r] then table.insert(e.r, r); have[r] = true end
      end
      save_outcomes(o)
      return
    end
  end
  table.insert(o, {m = msg, r = rs})
  save_outcomes(o)
end
local function mark_lost(g, now)
  redis.call('HSET', K, 'l:' .. g, now)
  local _, lost = fields()
  local n = count(lost)
  if n > MAX_LOST then
    local arr = {}
    for gg, t in pairs(lost) do table.insert(arr, {gg, t}) end
    table.sort(arr, function(x, y) return x[2] < y[2] end)
    for i = 1, n - MAX_LOST do redis.call('HDEL', K, 'l:' .. arr[i][1]) end
    redis.call('HSET', K, 'lost_dropped', now)
  end
end
local function sweep(now, except)
  local runs = fields()
  local n = 0
  for g, exp in pairs(runs) do
    if exp < now then
      redis.call('HDEL', K, 'r:' .. g)
      if g ~= except then
        mark_lost(g, now)
        n = n + 1
      end
    end
  end
  return n
end
-- Tombstones older than any scan can run (deadline + 5m) cannot belong to a
-- live run any more; they stop tainting the SBOM (Codex M72 R10 High-1).
local function prune_lost(now)
  local _, lost = fields()
  for g, t in pairs(lost) do
    if t < now - MAX_RUN_AGE then redis.call('HDEL', K, 'l:' .. g) end
  end
  local ld = tonumber(redis.call('HGET', K, 'lost_dropped') or '')
  if ld and ld < now - MAX_RUN_AGE then redis.call('HDEL', K, 'lost_dropped') end
end
local function publish(now)
  prune_lost(now)
  local runs, lost = fields()
  if count(runs) > 0 then
    redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now)
    return
  end
  local o = load_outcomes()
  local msgs, reasons, seen = {}, {}, {}
  local function add(m, rs)
    table.insert(msgs, m)
    for _, r in ipairs(rs) do
      if not seen[r] then seen[r] = true; table.insert(reasons, r) end
    end
  end
  for _, e in ipairs(o) do
    if type(e.m) == 'string' and e.m ~= '' then
      local rs = {}
      if type(e.r) == 'table' then rs = e.r end
      add(e.m, rs)
    end
  end
  if count(lost) > 0 or redis.call('HEXISTS', K, 'lost_dropped') == 1 then
    add(INTERRUPTED_MSG, {INTERRUPTED_REASON})
  end
  if #msgs > 0 then
    local rj = '[]'
    if #reasons > 0 then rj = cjson.encode(reasons) end
    redis.call('HSET', K, 'state', 'failed', 'error', table.concat(msgs, '; '), 'reasons', rj, 'updated', now)
  else
    redis.call('HSET', K, 'state', 'completed', 'error', '', 'reasons', '[]', 'updated', now)
  end
end
local function activate(g, now, lease)
  redis.call('HDEL', K, 'l:' .. g)
  redis.call('HSET', K, 'r:' .. g, now + tonumber(lease))
end
local function expire(ttl)
  redis.call('PEXPIRE', K, ttl)
end
`

// statusScripts are the store's Lua scripts, built for its MAX_RUN_AGE.
type statusScripts struct {
	begin, finish, merge, heartbeat, rejoin, mark, get *redis.Script
}

func newStatusScripts(maxRunAge time.Duration) *statusScripts {
	prelude := fmt.Sprintf("local INTERRUPTED_MSG = %q\nlocal INTERRUPTED_REASON = %q\nlocal MAX_LOST = %d\nlocal MAX_RUN_AGE = %d\n",
		scanInterruptedMarker, ScanReasonInterrupted, scanStatusMaxLost, maxRunAge.Milliseconds())
	mk := func(body string) *redis.Script { return redis.NewScript(prelude + scanStatusLua + body) }
	return &statusScripts{
		begin: mk(scanStatusBeginLua), finish: mk(scanStatusFinishLua), merge: mk(scanStatusMergeLua),
		heartbeat: mk(scanStatusHeartbeatLua), rejoin: mk(scanStatusRejoinLua), mark: mk(scanStatusMarkLua),
		get: mk(scanStatusGetLua),
	}
}

// ARGV: gen, lease ms, ttl ms.
const scanStatusBeginLua = `
local now = nowms()
sweep(now, nil)
-- A begin of a run already swept as interrupted (a retried write) rejoins
-- the group instead of starting a new one (Codex M72 R8 High-1).
if redis.call('HEXISTS', K, 'l:' .. ARGV[1]) == 1 then
  activate(ARGV[1], now, ARGV[2])
  publish(now)
  expire(ARGV[3])
  return 1
end
if active_count() == 0 then
  -- A new group. Tombstones are kept: a run swept as interrupted may still be
  -- alive (a suspended process), so the SBOM must not read completed while it
  -- could still be writing (Codex M72 R10 High-1).
  redis.call('HDEL', K, 'state', 'error', 'reasons', 'updated')
  save_outcomes({})
end
activate(ARGV[1], now, ARGV[2])
redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now)
expire(ARGV[3])
return 1`

// ARGV: gen, ttl ms, error marker (empty = completed), reasons JSON.
// Returns 1 if the run was active or swept as interrupted, 2 if Redis did not
// know it (its begin never landed, or it lapsed and its tombstone expired). A
// failure is recorded EITHER WAY (Codex M72 R5 High-2): a failure is never
// dropped, at worst it is attributed to a later group — a conservative
// "failed", never a false "completed".
const scanStatusFinishLua = `
local now = nowms()
local active = redis.call('HDEL', K, 'r:' .. ARGV[1]) == 1
sweep(now, ARGV[1])
local wasLost = redis.call('HDEL', K, 'l:' .. ARGV[1]) == 1
local ok, rs = pcall(cjson.decode, ARGV[4])
if not ok or type(rs) ~= 'table' then rs = {} end
add_failure(ARGV[3], rs)
publish(now)
expire(ARGV[2])
if active or wasLost then return 1 end
return 2`

// ARGV: JSON {"b": [gen...], "f": [gen...], "x": [[marker, [reason...]]...]},
// lease ms, ttl ms. The coalesced writes of a queue that overflowed: runs
// that began (joined to the current group, never a new one), runs that
// finished, and the failures among them (Codex M72 R5 High-3).
const scanStatusMergeLua = `
local now = nowms()
local ok, m = pcall(cjson.decode, ARGV[1])
if not ok or type(m) ~= 'table' then return redis.error_reply('bad merge') end
sweep(now, nil)
if type(m.b) == 'table' then
  for _, g in ipairs(m.b) do activate(g, now, ARGV[2]) end
end
if type(m.f) == 'table' then
  for _, g in ipairs(m.f) do
    redis.call('HDEL', K, 'r:' .. g, 'l:' .. g)
  end
end
if type(m.x) == 'table' then
  for _, x in ipairs(m.x) do
    if type(x) == 'table' and type(x[1]) == 'string' then
      local rs = {}
      if type(x[2]) == 'table' then rs = x[2] end
      add_failure(x[1], rs)
    end
  end
end
publish(now)
expire(ARGV[3])
return 1`

// ARGV: gen, lease ms, ttl ms. Returns 1 while the run is (again) active, 0
// when Redis does not know it.
const scanStatusHeartbeatLua = `
local now = nowms()
if redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 1 then
  activate(ARGV[1], now, ARGV[2])
  expire(ARGV[3])
  return 1
end
if redis.call('HEXISTS', K, 'l:' .. ARGV[1]) == 1 then
  -- swept as interrupted while it was alive: revive it
  activate(ARGV[1], now, ARGV[2])
  publish(now)
  expire(ARGV[3])
  return 1
end
return 0`

// ARGV: gen, lease ms, ttl ms. A run that is alive but not active in Redis
// (its tombstone was dropped, or the entry expired) joins the CURRENT group
// again: unlike Begin it never starts a new group, so the group's failures
// and interruptions are kept (Codex M72 R4 High-3).
const scanStatusRejoinLua = `
local now = nowms()
sweep(now, ARGV[1])
activate(ARGV[1], now, ARGV[2])
publish(now)
expire(ARGV[3])
return 1`

// ARGV: state, error, reasons JSON, ttl ms. A terminal state set outside a
// run (MarkFailed / MarkCompleted): ends every run of the group.
const scanStatusMarkLua = `
redis.call('DEL', K)
redis.call('HSET', K, 'state', ARGV[1], 'error', ARGV[2], 'reasons', ARGV[3], 'updated', nowms())
save_outcomes({})
expire(ARGV[4])
return 1`

// Returns false (nil) when there is no entry, else {state, error, reasons}.
const scanStatusGetLua = `
if redis.call('EXISTS', K) == 0 then return false end
local now = nowms()
local changed = sweep(now, nil) > 0
if not changed and redis.call('HGET', K, 'state') == 'running' and active_count() == 0 then
  -- running with no active run and none just swept: interrupted, without a
  -- run to revive.
  redis.call('HSET', K, 'lost_dropped', now)
  changed = true
end
if changed then publish(now) end
return {redis.call('HGET', K, 'state') or '', redis.call('HGET', K, 'error') or '', redis.call('HGET', K, 'reasons') or '[]'}`

// scanStatusStore is what the tracker needs from shared storage.
type scanStatusStore interface {
	begin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	// finish records run gen's outcome; known is false when the store did
	// not know the run (its failure is recorded anyway).
	finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (known bool, err error)
	// heartbeatMany renews the leases of runs in one round trip; active[i]
	// is false for a run that was superseded.
	heartbeatMany(ctx context.Context, runs []runKey) (active []bool, err error)
	// rejoin makes a live run active again in the current group.
	rejoin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	// merge applies a coalesced overflow (see scanStatusMerge).
	merge(ctx context.Context, sbomID uuid.UUID, m *mergeSet) error
	mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error
	get(ctx context.Context, sbomID uuid.UUID) (state ScanState, errMsg string, reasons []string, found bool, err error)
}

type redisScanStatusStore struct {
	client  *redis.Client
	ttl     time.Duration
	lease   time.Duration
	scripts *statusScripts
}

func (s *redisScanStatusStore) opCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	// Detached from the caller's cancellation: a status write at the end of
	// a cancelled scan must still be attempted (bounded).
	ctx = sbomredis.WithBreakerClass(context.WithoutCancel(ctx), sbomredis.ClassStatus)
	return sbomredis.OpContext(ctx, scanStatusOpTimeout)
}

func genString(gen uint64) string { return strconv.FormatUint(gen, 10) }

func reasonsJSON(reasons []string) string {
	if len(reasons) == 0 {
		return "[]"
	}
	b, err := json.Marshal(reasons)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func (s *redisScanStatusStore) begin(ctx context.Context, sbomID uuid.UUID, gen uint64) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.scripts.begin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	n, err := s.scripts.finish.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.ttl.Milliseconds(), errMsg, reasonsJSON(reasons)).Int()
	return n == 1, err
}

// mergeSet is a queue overflow's coalesced writes, as their NET effect (Codex
// M72 R6 High-1): the runs that began and are still live, the runs that
// finished whose begin was written before, and the failures. A run that began
// and finished inside the overflow leaves only its failure. Its size is
// therefore bounded by the runs live at once plus the queue before it, not by
// how many writes were folded in.
type mergeSet struct {
	begins   map[uint64]bool
	finishes map[uint64]bool
	failures []mergeFailure
}

type mergeFailure struct {
	msg     string
	reasons []string
}

func newMergeSet() *mergeSet {
	return &mergeSet{begins: map[uint64]bool{}, finishes: map[uint64]bool{}}
}

func (m *mergeSet) begin(gen uint64) { m.begins[gen] = true }

func (m *mergeSet) finish(gen uint64) {
	if m.begins[gen] {
		delete(m.begins, gen)
		return
	}
	m.finishes[gen] = true
}

func (m *mergeSet) addFailure(msg string, reasons []string) {
	for i := range m.failures {
		if m.failures[i].msg == msg {
			for _, r := range reasons {
				if !slices.Contains(m.failures[i].reasons, r) {
					m.failures[i].reasons = append(m.failures[i].reasons, r)
				}
			}
			return
		}
	}
	m.failures = append(m.failures, mergeFailure{msg, append([]string(nil), reasons...)})
}

func (m *mergeSet) clone() *mergeSet {
	c := newMergeSet()
	maps.Copy(c.begins, m.begins)
	maps.Copy(c.finishes, m.finishes)
	for _, f := range m.failures {
		c.failures = append(c.failures, mergeFailure{f.msg, slices.Clone(f.reasons)})
	}
	return c
}

func (m *mergeSet) json() string {
	gens := func(set map[uint64]bool) []string {
		out := make([]string, 0, len(set))
		for _, g := range slices.Sorted(maps.Keys(set)) {
			out = append(out, genString(g))
		}
		return out
	}
	x := make([][]any, 0, len(m.failures))
	for _, f := range m.failures {
		r := f.reasons
		if r == nil {
			r = []string{}
		}
		x = append(x, []any{f.msg, r})
	}
	b, err := json.Marshal(map[string]any{"b": gens(m.begins), "f": gens(m.finishes), "x": x})
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (s *redisScanStatusStore) merge(ctx context.Context, sbomID uuid.UUID, m *mergeSet) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.scripts.merge.Run(ctx, s.client, scanStatusKeys(sbomID),
		m.json(), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	// EVALSHA in one pipeline; the script is loaded only after NOSCRIPT, each
	// round trip under its own bound (Codex M72 R12 Medium-2: loading it every
	// pass shared the pass's deadline, and its success reset the breaker's
	// count each time).
	run := func() ([]*redis.Cmd, error) {
		octx, cancel := s.opCtx(ctx)
		defer cancel()
		cmds := make([]*redis.Cmd, len(runs))
		_, err := s.client.Pipelined(octx, func(p redis.Pipeliner) error {
			for i, r := range runs {
				cmds[i] = s.scripts.heartbeat.EvalSha(octx, p, scanStatusKeys(r.sbom),
					genString(r.gen), s.lease.Milliseconds(), s.ttl.Milliseconds())
			}
			return nil
		})
		return cmds, err
	}
	cmds, err := run()
	if err != nil && redis.HasErrorPrefix(err, "NOSCRIPT") {
		lctx, cancel := s.opCtx(ctx)
		lerr := s.scripts.heartbeat.Load(lctx, s.client).Err()
		cancel()
		if lerr != nil {
			return nil, lerr
		}
		cmds, err = run()
	}
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(runs))
	for i, c := range cmds {
		n, err := c.Int()
		if err != nil {
			return nil, err
		}
		out[i] = n == 1
	}
	return out, nil
}

func (s *redisScanStatusStore) rejoin(ctx context.Context, sbomID uuid.UUID, gen uint64) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.scripts.rejoin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.scripts.mark.Run(ctx, s.client, scanStatusKeys(sbomID),
		string(state), errMsg, reasonsJSON(reasons), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) get(ctx context.Context, sbomID uuid.UUID) (ScanState, string, []string, bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	v, err := s.scripts.get.Run(ctx, s.client, scanStatusKeys(sbomID)).StringSlice()
	if errors.Is(err, redis.Nil) {
		return ScanStateUnknown, "", nil, false, nil
	}
	if err != nil {
		return ScanStateUnknown, "", nil, false, err
	}
	if len(v) != 3 {
		return ScanStateUnknown, "", nil, false, fmt.Errorf("scan status: unexpected reply of %d values", len(v))
	}
	state := ScanState(v[0])
	switch state {
	case ScanStateRunning, ScanStateCompleted, ScanStateFailed:
	default:
		return ScanStateUnknown, "", nil, false, fmt.Errorf("scan status: unexpected state %q", v[0])
	}
	if state != ScanStateFailed {
		return state, "", nil, true, nil
	}
	var reasons []string
	if err := json.Unmarshal([]byte(v[2]), &reasons); err != nil {
		reasons = nil
	}
	return state, v[1], reasons, true, nil
}
