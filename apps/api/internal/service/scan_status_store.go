package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// Per SBOM, three keys sharing a hash tag (one Redis Cluster slot):
//
//	scanstatus1:{<sbom>}       HASH  state, error, reasons (JSON), updated,
//	                                 outcomes (JSON: the distinct failures of
//	                                 the current group), lost_dropped
//	scanstatus1:{<sbom>}:runs  ZSET  the active runs (member: run generation,
//	                                 score: lease expiry, ms of Redis time)
//	scanstatus1:{<sbom>}:lost  ZSET  runs swept as interrupted (at most 64)
//
// All expire after the tracker's retention (scan deadline + 15m, at least
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

func scanStatusKeys(sbomID uuid.UUID) []string {
	k := scanStatusPrefix + "{" + sbomID.String() + "}"
	return []string{k, k + ":runs", k + ":lost"}
}

// scanStatusLua is shared by every script. KEYS[1] the hash, KEYS[2] the
// active runs, KEYS[3] the runs swept as interrupted (ZSET gen -> sweep time,
// at most MAX_LOST newest; hash field lost_dropped=1 once one was dropped).
//
// outcomes holds only FAILURES, once per distinct marker (their reasons
// merged), so it is bounded by the marker vocabulary (Codex M72 R2 High-3);
// interrupted runs are counted through KEYS[3] instead of one outcome each, so
// they are bounded too (Codex M72 R3 Medium-2).
const scanStatusLua = `
local K, R, L = KEYS[1], KEYS[2], KEYS[3]
local function nowms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
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
  redis.call('ZADD', L, now, g)
  local n = redis.call('ZCARD', L)
  if n > MAX_LOST then
    redis.call('ZREMRANGEBYRANK', L, 0, n - MAX_LOST - 1)
    redis.call('HSET', K, 'lost_dropped', '1')
  end
end
local function sweep(now, except)
  local lost = redis.call('ZRANGEBYSCORE', R, '-inf', '(' .. now)
  if #lost == 0 then return 0 end
  redis.call('ZREMRANGEBYSCORE', R, '-inf', '(' .. now)
  local n = 0
  for _, g in ipairs(lost) do
    if g ~= except then
      mark_lost(g, now)
      n = n + 1
    end
  end
  return n
end
local function publish(now)
  if redis.call('ZCARD', R) > 0 then
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
  if redis.call('ZCARD', L) > 0 or redis.call('HGET', K, 'lost_dropped') == '1' then
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
local function expire(ttl)
  redis.call('PEXPIRE', K, ttl)
  redis.call('PEXPIRE', R, ttl)
  redis.call('PEXPIRE', L, ttl)
end
`

func scanStatusScript(body string) *redis.Script {
	prelude := fmt.Sprintf("local INTERRUPTED_MSG = %q\nlocal INTERRUPTED_REASON = %q\nlocal MAX_LOST = %d\n",
		scanInterruptedMarker, ScanReasonInterrupted, scanStatusMaxLost)
	return redis.NewScript(prelude + scanStatusLua + body)
}

// ARGV: gen, lease ms, ttl ms.
var scanStatusBegin = scanStatusScript(`
local now = nowms()
sweep(now, nil)
if redis.call('ZCARD', R) == 0 then
  redis.call('DEL', K, L)
  save_outcomes({})
end
redis.call('ZADD', R, now + tonumber(ARGV[2]), ARGV[1])
redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now)
expire(ARGV[3])
return 1`)

// ARGV: gen, ttl ms, error marker (” = completed), reasons JSON.
// Returns 1 if recorded, 0 if the run was not (or no longer) part of the group.
var scanStatusFinish = scanStatusScript(`
local now = nowms()
local exists = redis.call('EXISTS', K) == 1
local active = redis.call('ZREM', R, ARGV[1]) == 1
sweep(now, ARGV[1])
local wasLost = redis.call('ZREM', L, ARGV[1]) == 1
if not active and exists and not wasLost then
  -- Only a run swept as interrupted (its process lost Redis for longer than
  -- the lease) may still report; anything else was superseded.
  return 0
end
local ok, rs = pcall(cjson.decode, ARGV[4])
if not ok or type(rs) ~= 'table' then rs = {} end
add_failure(ARGV[3], rs)
publish(now)
expire(ARGV[2])
return 1`)

// ARGV: gen, lease ms, ttl ms. Returns 1 while the run is (again) active, 0
// when it was superseded.
var scanStatusHeartbeat = scanStatusScript(`
local now = nowms()
if redis.call('ZSCORE', R, ARGV[1]) then
  redis.call('ZADD', R, 'XX', now + tonumber(ARGV[2]), ARGV[1])
  expire(ARGV[3])
  return 1
end
if redis.call('ZREM', L, ARGV[1]) == 1 then
  -- swept as interrupted while it was alive: revive it
  redis.call('ZADD', R, now + tonumber(ARGV[2]), ARGV[1])
  publish(now)
  expire(ARGV[3])
  return 1
end
return 0`)

// ARGV: gen, lease ms, ttl ms. A run that is alive but no longer active in
// Redis (its lease ran out and its identity was dropped from the capped lost
// set, or a new group started meanwhile) joins the CURRENT group again: unlike
// Begin it never starts a new group, so the group's failures and
// interruptions are kept (Codex M72 R4 High-3).
var scanStatusRejoin = scanStatusScript(`
local now = nowms()
sweep(now, ARGV[1])
redis.call('ZREM', L, ARGV[1])
redis.call('ZADD', R, now + tonumber(ARGV[2]), ARGV[1])
publish(now)
expire(ARGV[3])
return 1`)

// ARGV: state, error, reasons JSON, ttl ms. A terminal state set outside a
// run (MarkFailed / MarkCompleted): ends every run of the group.
var scanStatusMark = scanStatusScript(`
redis.call('DEL', R, L)
redis.call('HDEL', K, 'lost_dropped')
redis.call('HSET', K, 'state', ARGV[1], 'error', ARGV[2], 'reasons', ARGV[3], 'updated', nowms())
save_outcomes({})
expire(ARGV[4])
return 1`)

// Returns false (nil) when there is no entry, else {state, error, reasons}.
var scanStatusGet = scanStatusScript(`
if redis.call('EXISTS', K) == 0 then return false end
local now = nowms()
local changed = sweep(now, nil) > 0
if not changed and redis.call('HGET', K, 'state') == 'running' and redis.call('ZCARD', R) == 0 then
  -- running with no active run and none just swept (the runs key itself was
  -- lost): interrupted, without a run to revive.
  redis.call('HSET', K, 'lost_dropped', '1')
  changed = true
end
if changed then
  publish(now)
  -- The lost-run key a read creates expires with the entry (Codex M72 R4
  -- Medium-4).
  local ttl = redis.call('PTTL', K)
  if ttl > 0 then redis.call('PEXPIRE', L, ttl) end
end
return {redis.call('HGET', K, 'state') or '', redis.call('HGET', K, 'error') or '', redis.call('HGET', K, 'reasons') or '[]'}`)

// scanStatusStore is what the tracker needs from shared storage.
type scanStatusStore interface {
	begin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (recorded bool, err error)
	// heartbeatMany renews the leases of runs in one round trip; active[i]
	// is false for a run that was superseded.
	heartbeatMany(ctx context.Context, runs []runKey) (active []bool, err error)
	// rejoin makes a live run active again in the current group.
	rejoin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error
	get(ctx context.Context, sbomID uuid.UUID) (state ScanState, errMsg string, reasons []string, found bool, err error)
}

type redisScanStatusStore struct {
	client *redis.Client
	ttl    time.Duration
	lease  time.Duration
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
	return scanStatusBegin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	n, err := scanStatusFinish.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.ttl.Milliseconds(), errMsg, reasonsJSON(reasons)).Int()
	return n == 1, err
}

func (s *redisScanStatusStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	if err := scanStatusHeartbeat.Load(ctx, s.client).Err(); err != nil {
		return nil, err
	}
	cmds := make([]*redis.Cmd, len(runs))
	_, err := s.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		for i, r := range runs {
			cmds[i] = scanStatusHeartbeat.EvalSha(ctx, p, scanStatusKeys(r.sbom),
				genString(r.gen), s.lease.Milliseconds(), s.ttl.Milliseconds())
		}
		return nil
	})
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
	return scanStatusRejoin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return scanStatusMark.Run(ctx, s.client, scanStatusKeys(sbomID),
		string(state), errMsg, reasonsJSON(reasons), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) get(ctx context.Context, sbomID uuid.UUID) (ScanState, string, []string, bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	v, err := scanStatusGet.Run(ctx, s.client, scanStatusKeys(sbomID)).StringSlice()
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
