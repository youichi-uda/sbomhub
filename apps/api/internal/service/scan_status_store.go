package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync/atomic"
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
//	p:<gen>       an intent: a Begin still queued behind older writes; reads
//	              as running, value = lease expiry
//	l:<gen>       a run swept as interrupted (a tombstone), value = sweep time;
//	              at most MAX_LOST (Codex M72 R3 Medium-2), they survive a new
//	              group and expire after MAX_RUN_AGE (Codex M72 R10 High-1)
//	lost_dropped  when a tombstone was dropped (or the runs were found lost)
//	born          when this incarnation of the key was created (+ nonce)
//	rev           write counter; the version is born:rev
//	young_hold    '1': the state was held running because the key is young;
//	              'c': completed while young without a hold (Redis could
//	              not evict), re-held if the holding scripts read it young
const scanStatusLua = `
local K = KEYS[1]
local function nowms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local function fields()
  local all = redis.call('HGETALL', K)
  local runs, lost, intents = {}, {}, {}
  for i = 1, #all, 2 do
    local f, v = all[i], all[i + 1]
    local p = string.sub(f, 1, 2)
    if p == 'r:' then
      runs[string.sub(f, 3)] = tonumber(v) or 0
    elseif p == 'l:' then
      lost[string.sub(f, 3)] = tonumber(v) or 0
    elseif p == 'p:' then
      intents[string.sub(f, 3)] = tonumber(v) or 0
    end
  end
  return runs, lost, intents
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
-- born: when this incarnation of the key was created, with Redis's
-- microseconds as a nonce. It is part of the version, so versions never repeat
-- after the key was evicted and recreated (Codex M72 R19 High-2).
local function ensure_born()
  if redis.call('HEXISTS', K, 'born') == 0 then
    local t = redis.call('TIME')
    redis.call('HSET', K, 'born', t[1] .. string.format('%06d', tonumber(t[2])))
  end
end
local function born_ms()
  local b = redis.call('HGET', K, 'born')
  if not b then return nil end
  return math.floor(tonumber(string.sub(b, 1, -7)) * 1000 + tonumber(string.sub(b, -6)) / 1000)
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
-- cap_lost keeps the MAX_LOST newest tombstones. One pass, one sort.
local function cap_lost(now)
  local _, lost = fields()
  local arr = {}
  for g, t in pairs(lost) do table.insert(arr, {g, t}) end
  if #arr <= MAX_LOST then return end
  table.sort(arr, function(x, y) return x[2] < y[2] end)
  local drop = {}
  for i = 1, #arr - MAX_LOST do table.insert(drop, 'l:' .. arr[i][1]) end
  for i = 1, #drop, 1000 do
    redis.call('HDEL', K, unpack(drop, i, math.min(i + 999, #drop)))
  end
  redis.call('HSET', K, 'lost_dropped', now)
end
-- sweep moves every expired run to a tombstone in ONE pass over the hash
-- (Codex M72 R15 Medium-3: one hash read per run was quadratic).
local function sweep(now, except)
  local runs, _, intents = fields()
  local n = 0
  local del, set = {}, {}
  for prefix, t in pairs({['r:'] = runs, ['p:'] = intents}) do
    for g, exp in pairs(t) do
      if exp < now then
        table.insert(del, prefix .. g)
        if g ~= except then
          table.insert(set, 'l:' .. g)
          table.insert(set, now)
          n = n + 1
        end
      end
    end
  end
  for i = 1, #del, 1000 do
    redis.call('HDEL', K, unpack(del, i, math.min(i + 999, #del)))
  end
  for i = 1, #set, 2000 do
    redis.call('HSET', K, unpack(set, i, math.min(i + 1999, #set)))
  end
  if n > 0 then cap_lost(now) end
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
  local runs, lost, intents = fields()
  -- An intent (a Begin written ahead of its queue) is running too.
  if count(runs) > 0 or count(intents) > 0 then
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
    redis.call('HDEL', K, 'young_hold')
    return
  end
  -- A key younger than one heartbeat may have replaced an evicted one whose
  -- runs have not rejoined yet: it does not read completed until they could
  -- have (Codex M72 R19 High-2).
  -- YOUNG is 0 while Redis cannot evict (the immediate scripts); such a
  -- young completion is marked 'c' so the holding scripts re-hold it if
  -- eviction becomes possible while the key is still young.
  -- A hold already in place ('1') is kept until the key is no longer young
  -- whichever scripts run (Codex M72 eviction R2 Medium-1): it may stand for
  -- a real eviction whose runs have not rejoined.
  local b = born_ms()
  local held = redis.call('HGET', K, 'young_hold') == '1'
  if b and (now - b < YOUNG or (held and now - b < YOUNG_SPAN)) then
    redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now, 'young_hold', '1')
    return
  end
  if b and now - b < YOUNG_SPAN then
    redis.call('HSET', K, 'state', 'completed', 'error', '', 'reasons', '[]', 'updated', now, 'young_hold', 'c')
    return
  end
  redis.call('HDEL', K, 'young_hold')
  redis.call('HSET', K, 'state', 'completed', 'error', '', 'reasons', '[]', 'updated', now)
end
local function activate(g, now, lease)
  redis.call('HDEL', K, 'l:' .. g, 'p:' .. g)
  redis.call('HSET', K, 'r:' .. g, now + tonumber(lease))
end
-- Every write bumps rev: the status version readers compare (Codex M72
-- R14 High-1; a millisecond time was not unique per write).
local function bump()
  redis.call('HINCRBY', K, 'rev', 1)
end
local function expire(ttl)
  bump()
  redis.call('PEXPIRE', K, ttl)
end
`

// statusScripts are the store's Lua scripts, built for its MAX_RUN_AGE.
type statusScripts struct {
	begin, finish, merge, heartbeat, rejoin, mark, get, intent *redis.Script
}

func newStatusScripts(maxRunAge time.Duration) *statusScripts {
	return newStatusScriptsYoung(maxRunAge, scanStatusYoung)
}

// scanStatusYoung: a status key younger than this does not read completed
// (see publish in scanStatusLua): two heartbeats plus slack, so a live run of
// an evicted key rejoins in time even if one renewal attempt fails (its
// rejoin is written out of line, Codex M72 R20 High-1).
const scanStatusYoung = 2*ScanStatusHeartbeat + 15*time.Second

func newStatusScriptsYoung(maxRunAge, young time.Duration) *statusScripts {
	return newStatusScriptsSpan(maxRunAge, young, young)
}

// newStatusScriptsSpan: young is the hold these scripts apply (0 for the
// immediate scripts); span is how long a key counts as young at all, so a
// completion inside it is marked for re-holding (see publish).
func newStatusScriptsSpan(maxRunAge, young, span time.Duration) *statusScripts {
	prelude := fmt.Sprintf("local INTERRUPTED_MSG = %q\nlocal INTERRUPTED_REASON = %q\nlocal MAX_LOST = %d\nlocal MAX_RUN_AGE = %d\nlocal YOUNG = %d\nlocal YOUNG_SPAN = %d\n",
		scanInterruptedMarker, ScanReasonInterrupted, scanStatusMaxLost, maxRunAge.Milliseconds(), young.Milliseconds(), span.Milliseconds())
	mk := func(body string) *redis.Script { return redis.NewScript(prelude + scanStatusLua + body) }
	return &statusScripts{
		begin: mk(scanStatusBeginLua), finish: mk(scanStatusFinishLua), merge: mk(scanStatusMergeLua),
		heartbeat: mk(scanStatusHeartbeatLua), rejoin: mk(scanStatusRejoinLua), mark: mk(scanStatusMarkLua),
		get: mk(scanStatusGetLua), intent: mk(scanStatusIntentLua),
	}
}

// ARGV: gen, lease ms, ttl ms.
const scanStatusBeginLua = `
local now = nowms()
ensure_born()
sweep(now, nil)
-- A begin of a run already swept as interrupted (a retried write) rejoins
-- the group instead of starting a new one (Codex M72 R8 High-1).
-- Likewise a Begin replacing its own intent: the intent already made the
-- run a member of the current group (Codex M72 R19 High-1).
if redis.call('HEXISTS', K, 'l:' .. ARGV[1]) == 1 or redis.call('HEXISTS', K, 'p:' .. ARGV[1]) == 1 then
  activate(ARGV[1], now, ARGV[2])
  publish(now)
  expire(ARGV[3])
  return 1
end
local runs_b, _, intents_b = fields()
intents_b[ARGV[1]] = nil
if count(runs_b) == 0 and count(intents_b) == 0 then
  -- A new group (no other run, and no intent: an intent is a member of the
  -- current group, Codex M72 R19 High-1). Tombstones are kept: a run swept as interrupted may still be
  -- alive (a suspended process), so the SBOM must not read completed while it
  -- could still be writing (Codex M72 R10 High-1).
  redis.call('HDEL', K, 'state', 'error', 'reasons', 'updated')
  save_outcomes({})
end
activate(ARGV[1], now, ARGV[2])
redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now)
expire(ARGV[3])
return 1`

// ARGV: gen, lease ms, ttl ms. An INTENT (Codex M72 R18 High-1): a Begin
// queued behind older writes of its SBOM is written ahead of them as p:<gen>,
// which reads as running (so those older writes cannot publish a terminal
// state meanwhile) but takes no part in group decisions; the queued Begin
// replaces it when applied. An intent whose lease runs out is swept as
// interrupted, like a run.
const scanStatusIntentLua = `
local now = nowms()
ensure_born()
sweep(now, nil)
if redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 1 then return 0 end
redis.call('HSET', K, 'p:' .. ARGV[1], now + tonumber(ARGV[2]))
publish(now)
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
ensure_born()
local active = redis.call('HDEL', K, 'r:' .. ARGV[1]) == 1
if redis.call('HDEL', K, 'p:' .. ARGV[1]) == 1 then active = true end
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
ensure_born()
local ok, m = pcall(cjson.decode, ARGV[1])
if not ok or type(m) ~= 'table' then return redis.error_reply('bad merge') end
sweep(now, nil)
if type(m.b) == 'table' then
  for _, g in ipairs(m.b) do activate(g, now, ARGV[2]) end
end
if type(m.f) == 'table' then
  for _, g in ipairs(m.f) do
    redis.call('HDEL', K, 'r:' .. g, 'l:' .. g, 'p:' .. g)
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
if redis.call('HEXISTS', K, 'p:' .. ARGV[1]) == 1 then
  -- an intent whose Begin is still queued: renew it as an intent
  redis.call('HSET', K, 'p:' .. ARGV[1], now + tonumber(ARGV[2]))
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
ensure_born()
sweep(now, ARGV[1])
activate(ARGV[1], now, ARGV[2])
publish(now)
expire(ARGV[3])
return 1`

// ARGV: state, error, reasons JSON, ttl ms. A terminal state set outside a
// run (MarkFailed / MarkCompleted): ends every run of the group.
const scanStatusMarkLua = `
local rev = redis.call('HGET', K, 'rev')
local born = redis.call('HGET', K, 'born')
redis.call('DEL', K)
if rev then redis.call('HSET', K, 'rev', rev) end
if born then redis.call('HSET', K, 'born', born) else ensure_born() end
redis.call('HSET', K, 'state', ARGV[1], 'error', ARGV[2], 'reasons', ARGV[3], 'updated', nowms())
save_outcomes({})
expire(ARGV[4])
return 1`

// Returns false (nil) when there is no entry, else {state, error, reasons,
// rev}.
const scanStatusGetLua = `
if redis.call('EXISTS', K) == 0 then return false end
local now = nowms()
local changed = sweep(now, nil) > 0
local runs_now, _, intents_now = fields()
local idle = count(runs_now) == 0 and count(intents_now) == 0
local yh = redis.call('HGET', K, 'young_hold')
if not changed and idle and yh == '1' then
  -- held as running while the key was young: re-evaluate once it is not
  local b = born_ms()
  if not b or (now - b >= YOUNG and now - b >= YOUNG_SPAN) then changed = true end
elseif not changed and idle and yh == 'c' then
  -- completed young under the immediate scripts: hold it now if these
  -- scripts hold and the key is still young
  local b = born_ms()
  if b and now - b < YOUNG then changed = true end
elseif not changed and idle and redis.call('HGET', K, 'state') == 'running' then
  -- running with no active run and none just swept: interrupted, without a
  -- run to revive.
  redis.call('HSET', K, 'lost_dropped', now)
  changed = true
end
if changed then
  publish(now)
  bump()
end
return {redis.call('HGET', K, 'state') or '', redis.call('HGET', K, 'error') or '', redis.call('HGET', K, 'reasons') or '[]', (redis.call('HGET', K, 'born') or '') .. ':' .. (redis.call('HGET', K, 'rev') or '')}`

// statusView is one read of the shared status. version changes with every
// write of it (the entry's rev counter).
type statusView struct {
	state   ScanState
	errMsg  string
	reasons []string
	version string
	found   bool
}

// scanStatusStore is what the tracker needs from shared storage.
type scanStatusStore interface {
	begin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	// finish records run gen's outcome; known is false when the store did
	// not know the run (its failure is recorded anyway).
	finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (known bool, err error)
	// heartbeatMany renews the leases of runs in one round trip; active[i]
	// is false for a run that was superseded.
	heartbeatMany(ctx context.Context, runs []runKey) (active []bool, err error)
	// intent marks a Begin queued behind older writes as running at once.
	intent(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	// rejoin makes a live run active again in the current group.
	rejoin(ctx context.Context, sbomID uuid.UUID, gen uint64) error
	// merge applies a coalesced overflow (see scanStatusMerge).
	merge(ctx context.Context, sbomID uuid.UUID, m *mergeSet) error
	mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error
	get(ctx context.Context, sbomID uuid.UUID) (statusView, error)
}

type redisScanStatusStore struct {
	client *redis.Client
	ttl    time.Duration
	lease  time.Duration
	// scripts hold a young key's completed back as running (scanStatusYoung);
	// immediate do not. The hold only guards against an evicted key, so
	// immediate are used while Redis reports it cannot evict (CI Web E2E at
	// 6ed0ece: every fast scan of a new SBOM read running for 75s).
	scripts   *statusScripts
	immediate *statusScripts
	// noEvict: the last probe found maxmemory 0 or policy noeviction.
	// Unknown (no probe yet, CONFIG refused, Redis down) counts as false.
	noEvict atomic.Bool
	// immediateFrom (monoNow): the immediate scripts are not used before it.
	// Set one young span ahead when Redis stops being able to evict (Codex M72
	// eviction R3 Medium-1: a key created under the holding scripts may stand
	// for an eviction whose runs have not rejoined).
	immediateFrom atomic.Int64
	// probe enables the periodic CONFIG GET (off for stores built in tests).
	probe     bool
	probeAt   atomic.Int64
	probeBusy atomic.Bool
}

// evictionProbeEvery: how often the store re-reads Redis's eviction settings
// (CONFIG SET can change them at runtime).
const evictionProbeEvery = 30 * time.Second

func (s *redisScanStatusStore) initScripts(maxRunAge time.Duration) {
	s.scripts = newStatusScripts(maxRunAge)
	s.immediate = newStatusScriptsSpan(maxRunAge, 0, scanStatusYoung)
}

// sc returns the scripts to run now.
func (s *redisScanStatusStore) sc() *statusScripts {
	if s.probe {
		s.maybeProbe()
	}
	if s.immediate != nil && s.noEvict.Load() && monoNow() >= s.immediateFrom.Load() {
		return s.immediate
	}
	return s.scripts
}

// monoEpoch anchors monoNow: time.Since uses the monotonic clock, so a
// wall-clock step cannot stall the re-probe (Codex M72 eviction R2 Low-1).
var monoEpoch = time.Now()

func monoNow() int64 { return int64(time.Since(monoEpoch)) }

func (s *redisScanStatusStore) probeDue() bool {
	at := s.probeAt.Load()
	return at == 0 || monoNow()-at >= int64(evictionProbeEvery) // 0: never probed
}

// probeNow reads the eviction settings and waits for the answer (bounded by
// the store's operation timeout): used once, before the first scan (Codex
// M72 eviction R1 Medium-1).
func (s *redisScanStatusStore) probeNow() {
	s.probeAt.Store(monoNow())
	s.setNoEvict(s.probeNoEviction(), true)
}

// setNoEvict records a probe's answer. A later answer that turns "can evict
// (or unknown)" into "cannot evict" delays the immediate scripts by one young
// span; the initial answer applies at once.
func (s *redisScanStatusStore) setNoEvict(v, initial bool) {
	if v && !initial && !s.noEvict.Load() {
		s.immediateFrom.Store(monoNow() + int64(scanStatusYoung))
	}
	s.noEvict.Store(v)
}

// maybeProbe re-reads the eviction settings in the background when the last
// read is older than evictionProbeEvery. It never delays the caller.
func (s *redisScanStatusStore) maybeProbe() {
	if !s.probeDue() {
		return
	}
	if !s.probeBusy.CompareAndSwap(false, true) {
		return
	}
	s.probeAt.Store(monoNow())
	go func() {
		defer s.probeBusy.Store(false)
		s.setNoEvict(s.probeNoEviction(), false)
	}()
}

// probeNoEviction reports whether Redis says it cannot evict a key. Any
// error (CONFIG disabled on managed Redis, Redis down) answers false.
func (s *redisScanStatusStore) probeNoEviction() bool {
	// Outside every breaker (Codex M72 eviction R1 Medium-3): a refused
	// CONFIG says nothing about the status scripts' health.
	ctx, cancel := s.opCtx(context.Background())
	defer cancel()
	ctx = sbomredis.WithoutBreaker(ctx)
	cfg, err := s.client.ConfigGet(ctx, "maxmemory*").Result()
	if err != nil {
		return false
	}
	return redisCannotEvict(cfg)
}

// redisCannotEvict: Redis evicts keys only when maxmemory is set and the
// policy is not noeviction. An incomplete answer counts as "can evict".
func redisCannotEvict(cfg map[string]string) bool {
	mm, okM := cfg["maxmemory"]
	pol, okP := cfg["maxmemory-policy"]
	if !okM || !okP {
		return false
	}
	return mm == "0" || pol == "noeviction"
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
	return s.sc().begin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) finish(ctx context.Context, sbomID uuid.UUID, gen uint64, errMsg string, reasons []string) (bool, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	n, err := s.sc().finish.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.ttl.Milliseconds(), errMsg, reasonsJSON(reasons)).Int()
	return n == 1, err
}

// mergeSet is a queue overflow's coalesced writes, as their NET effect (Codex
// M72 R6 High-1): the runs that began and are still live, the runs that
// finished, and the failures. Its size is bounded by the runs of the SBOM
// seen during the overflow, not by how many writes were folded in.
type mergeSet struct {
	begins   map[uint64]bool
	finishes map[uint64]bool
	// fresh: runs whose FIRST write (their Begin) was folded into this merge.
	// No earlier write of theirs is queued or applied, so when such a run also
	// finishes inside the merge it leaves nothing but its failure (Codex M72
	// R16 High-2) — the merge stays bounded by the runs live at once plus the
	// writes queued before it, however many requests arrive.
	fresh         map[uint64]bool
	freshFinishes int
	failures      []mergeFailure
}

type mergeFailure struct {
	msg     string
	reasons []string
}

func newMergeSet() *mergeSet {
	return &mergeSet{begins: map[uint64]bool{}, finishes: map[uint64]bool{}, fresh: map[uint64]bool{}}
}

// begin folds a Begin (fresh: the run's first write) or a rejoin.
func (m *mergeSet) begin(gen uint64, fresh bool) {
	m.begins[gen] = true
	if fresh {
		m.fresh[gen] = true
	}
}

// finish folds a Finish. A run that began fresh inside this merge is netted
// away; any other removal is always written (Codex M72 R14 Medium-4: an
// earlier queued rejoin may have activated it in Redis).
func (m *mergeSet) finish(gen uint64) {
	delete(m.begins, gen)
	if m.fresh[gen] {
		delete(m.fresh, gen)
		// Its Begin was queued behind others, so an intent of it may be in
		// Redis: its removal is written too (Codex M72 R19 Medium-3), up to
		// maxFreshFinishes per merge; beyond that its intent expires and is
		// swept as interrupted — conservative, and the merge stays bounded.
		if m.freshFinishes >= maxFreshFinishes {
			return
		}
		m.freshFinishes++
	}
	m.finishes[gen] = true
}

// maxFreshFinishes bounds the removals one merge writes for runs that began
// and ended inside it.
const maxFreshFinishes = 1024

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
	return s.sc().merge.Run(ctx, s.client, scanStatusKeys(sbomID),
		m.json(), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) heartbeatMany(ctx context.Context, runs []runKey) ([]bool, error) {
	// EVALSHA in one pipeline; the script is loaded only after NOSCRIPT, each
	// round trip under its own bound (Codex M72 R12 Medium-2: loading it every
	// pass shared the pass's deadline, and its success reset the breaker's
	// count each time). One script set for the whole call, so the script
	// loaded after NOSCRIPT is the one run again.
	hb := s.sc().heartbeat
	run := func() ([]*redis.Cmd, error) {
		octx, cancel := s.opCtx(ctx)
		defer cancel()
		cmds := make([]*redis.Cmd, len(runs))
		_, err := s.client.Pipelined(octx, func(p redis.Pipeliner) error {
			for i, r := range runs {
				cmds[i] = hb.EvalSha(octx, p, scanStatusKeys(r.sbom),
					genString(r.gen), s.lease.Milliseconds(), s.ttl.Milliseconds())
			}
			return nil
		})
		return cmds, err
	}
	cmds, err := run()
	if err != nil && redis.HasErrorPrefix(err, "NOSCRIPT") {
		lctx, cancel := s.opCtx(ctx)
		lerr := hb.Load(lctx, s.client).Err()
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

func (s *redisScanStatusStore) intent(ctx context.Context, sbomID uuid.UUID, gen uint64) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.sc().intent.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) rejoin(ctx context.Context, sbomID uuid.UUID, gen uint64) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.sc().rejoin.Run(ctx, s.client, scanStatusKeys(sbomID),
		genString(gen), s.lease.Milliseconds(), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) mark(ctx context.Context, sbomID uuid.UUID, state ScanState, errMsg string, reasons []string) error {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	return s.sc().mark.Run(ctx, s.client, scanStatusKeys(sbomID),
		string(state), errMsg, reasonsJSON(reasons), s.ttl.Milliseconds()).Err()
}

func (s *redisScanStatusStore) get(ctx context.Context, sbomID uuid.UUID) (statusView, error) {
	ctx, cancel := s.opCtx(ctx)
	defer cancel()
	v, err := s.sc().get.Run(ctx, s.client, scanStatusKeys(sbomID)).StringSlice()
	if errors.Is(err, redis.Nil) {
		return statusView{}, nil
	}
	if err != nil {
		return statusView{}, err
	}
	if len(v) != 4 {
		return statusView{}, fmt.Errorf("scan status: unexpected reply of %d values", len(v))
	}
	state := ScanState(v[0])
	switch state {
	case ScanStateRunning, ScanStateCompleted, ScanStateFailed:
	default:
		return statusView{}, fmt.Errorf("scan status: unexpected state %q", v[0])
	}
	view := statusView{state: state, version: "s" + v[3], found: true}
	if state != ScanStateFailed {
		return view, nil
	}
	view.errMsg = v[1]
	if err := json.Unmarshal([]byte(v[2]), &view.reasons); err != nil {
		view.reasons = nil
	}
	return view, nil
}
