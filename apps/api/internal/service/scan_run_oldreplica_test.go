//go:build integration

package service

// The scan-status scripts of a3a785e (the checked_sources release, the last
// one without scan_run), verbatim: an OLDER replica during a rolling upgrade,
// for the scan_run compatibility tests (scan_run_redis_integration_test.go).

const prevScanStatusLua = `
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
-- The group's skipped sources live in the outcomes entry with an empty
-- marker (see the key layout above).
local function skipped_list()
  for _, e in ipairs(load_outcomes()) do
    if e.m == '' and type(e.s) == 'table' then return e.s end
  end
  return {}
end
local function add_skipped(ss)
  if type(ss) ~= 'table' or #ss == 0 then return end
  local o = load_outcomes()
  local entry = nil
  for _, e in ipairs(o) do
    if e.m == '' and type(e.s) == 'table' then entry = e; break end
  end
  if not entry then
    entry = {m = '', s = {}}
    table.insert(o, entry)
  end
  local have = {}
  for _, x in ipairs(entry.s) do have[x] = true end
  for _, x in ipairs(ss) do
    if type(x) == 'string' and x ~= '' and not have[x] then table.insert(entry.s, x); have[x] = true end
  end
  save_outcomes(o)
end
-- The group's checked sources: c of the marker-less entry; nil while no
-- finish of the group reported coverage.
local function checked_list()
  local c = nil
  for _, e in ipairs(load_outcomes()) do
    if e.m == '' then
      -- u: the group's coverage became unknown (see coverage_unknown).
      if e.u then return nil end
      if c == nil and type(e.c) == 'table' then c = e.c end
    end
  end
  return c
end
-- coverage_unknown: the group lost what its earlier finishes reported (a
-- live run rejoined after its identity, or the whole key, was lost; or a
-- legacy Mark* was folded into a merge), so no report may stand for the
-- group's coverage until a new group begins (Codex coverage R2 High-1 /
-- Medium-2). Kept in the marker-less entry, so every reset clears it.
local function coverage_unknown()
  local o = load_outcomes()
  local entry = nil
  for _, e in ipairs(o) do
    if e.m == '' and type(e.s) == 'table' then entry = e; break end
  end
  if not entry then
    entry = {m = '', s = {}}
    table.insert(o, entry)
  end
  entry.u = true
  entry.c = nil
  save_outcomes(o)
end
-- add_checked intersects the group's checked sources with a finish's (the
-- first report sets them). cs is nil when the finish reports nothing.
-- may_set: the finish is known to be a member of the current group. A
-- finish that is not (a late write after an eviction or a long partition)
-- may narrow the group's checked sources but never set them: it may belong
-- to an earlier group (Codex coverage R1 High-2).
local function add_checked(cs, may_set)
  if type(cs) ~= 'table' then return end
  if type(checked_list()) ~= 'table' then
    if not may_set then return end
    for _, e in ipairs(load_outcomes()) do
      if e.m == '' and e.u then return end
    end
  end
  local o = load_outcomes()
  local entry = nil
  for _, e in ipairs(o) do
    if e.m == '' and type(e.s) == 'table' then entry = e; break end
  end
  if not entry then
    entry = {m = '', s = {}}
    table.insert(o, entry)
  end
  local inc = {}
  for _, x in ipairs(cs) do
    if type(x) == 'string' and x ~= '' then inc[x] = true end
  end
  local out, seen = {}, {}
  local base = cs
  if type(entry.c) == 'table' then base = entry.c end
  for _, x in ipairs(base) do
    if type(x) == 'string' and inc[x] and not seen[x] then table.insert(out, x); seen[x] = true end
  end
  entry.c = out
  save_outcomes(o)
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
  -- YOUNG > 0 guards: with no hold (YOUNG 0) a Redis clock step back must
  -- not make a negative age count as young (Codex M72 eviction R4 Low-1).
  if b and ((YOUNG > 0 and now - b < YOUNG) or (held and now - b < YOUNG_SPAN)) then
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

const prevScanStatusBeginLua = `
local now = nowms()
local lost_identity = ARGV[4] == '1' and redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 0 and
  redis.call('HEXISTS', K, 'p:' .. ARGV[1]) == 0 and redis.call('HEXISTS', K, 'l:' .. ARGV[1]) == 0
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
if redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 1 then lost_identity = false end
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
if lost_identity then coverage_unknown() end
activate(ARGV[1], now, ARGV[2])
redis.call('HSET', K, 'state', 'running', 'error', '', 'reasons', '[]', 'updated', now)
expire(ARGV[3])
return 1`

const prevScanStatusIntentLua = `
local now = nowms()
ensure_born()
sweep(now, nil)
if redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 1 then return 0 end
redis.call('HSET', K, 'p:' .. ARGV[1], now + tonumber(ARGV[2]))
publish(now)
expire(ARGV[3])
return 1`

const prevScanStatusFinishLua = `
local now = nowms()
ensure_born()
local active = redis.call('HDEL', K, 'r:' .. ARGV[1]) == 1
if redis.call('HDEL', K, 'p:' .. ARGV[1]) == 1 then active = true end
sweep(now, ARGV[1])
local wasLost = redis.call('HDEL', K, 'l:' .. ARGV[1]) == 1
local ok, rs = pcall(cjson.decode, ARGV[4])
if not ok or type(rs) ~= 'table' then rs = {} end
add_failure(ARGV[3], rs)
local okS, ss = pcall(cjson.decode, ARGV[5] or '[]')
if okS then add_skipped(ss) end
if ARGV[6] and ARGV[6] ~= '' then
  local okC, cs = pcall(cjson.decode, ARGV[6])
  if okC then add_checked(cs, active or wasLost) end
end
publish(now)
expire(ARGV[2])
if active or wasLost then return 1 end
return 2`

const prevScanStatusMergeLua = `
local now = nowms()
-- A merge always follows earlier writes of the SBOM (its queue overflowed),
-- so a missing key means it was lost: coverage unknown (Codex coverage R5
-- High-2).
local key_lost = redis.call('EXISTS', K) == 0
ensure_born()
local ok, m = pcall(cjson.decode, ARGV[1])
if not ok or type(m) ~= 'table' then return redis.error_reply('bad merge') end
sweep(now, nil)
if type(m.b) == 'table' then
  for _, g in ipairs(m.b) do activate(g, now, ARGV[2]) end
end
local member = {}
if type(m.f) == 'table' then
  for _, g in ipairs(m.f) do
    if redis.call('HDEL', K, 'r:' .. g, 'l:' .. g, 'p:' .. g) > 0 then member[g] = true end
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
add_skipped(m.s)
-- The folded checked sources (an intersection, so a subset of every folded
-- reporter's) may set the group's only when a reporter was a member.
local reporter_member = false
if type(m.cr) == 'table' then
  for _, g in ipairs(m.cr) do
    if member[g] then reporter_member = true end
  end
end
add_checked(m.c, reporter_member)
if m.cu or key_lost then coverage_unknown() end
publish(now)
expire(ARGV[3])
return 1`

const prevScanStatusHeartbeatLua = `
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

const prevScanStatusRejoinLua = `
local now = nowms()
ensure_born()
sweep(now, ARGV[1])
-- A run that is not active here lost its identity (or the key was lost):
-- what the group's earlier finishes reported may be gone with it.
if redis.call('HEXISTS', K, 'r:' .. ARGV[1]) == 0 then coverage_unknown() end
activate(ARGV[1], now, ARGV[2])
publish(now)
expire(ARGV[3])
return 1`

const prevScanStatusMarkLua = `
local rev = redis.call('HGET', K, 'rev')
local born = redis.call('HGET', K, 'born')
redis.call('DEL', K)
if rev then redis.call('HSET', K, 'rev', rev) end
if born then redis.call('HSET', K, 'born', born) else ensure_born() end
redis.call('HSET', K, 'state', ARGV[1], 'error', ARGV[2], 'reasons', ARGV[3], 'updated', nowms())
save_outcomes({})
expire(ARGV[4])
return 1`

const prevScanStatusGetLua = `
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
  if YOUNG > 0 and b and now - b < YOUNG then changed = true end
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
return {redis.call('HGET', K, 'state') or '', redis.call('HGET', K, 'error') or '', redis.call('HGET', K, 'reasons') or '[]', (redis.call('HGET', K, 'born') or '') .. ':' .. (redis.call('HGET', K, 'rev') or ''), (function()
  local sk = skipped_list()
  if #sk == 0 then return '[]' end
  return cjson.encode(sk)
end)(), (function()
  local cs = checked_list()
  if cs == nil then return '' end
  if #cs == 0 then return '[]' end
  return cjson.encode(cs)
end)()}`
