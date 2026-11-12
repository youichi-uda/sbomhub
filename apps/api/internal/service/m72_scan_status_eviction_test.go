package service

import "testing"

// CI Web E2E (6ed0ece): with the 75s young-key hold applied unconditionally,
// every scan of a new SBOM read running for 75s, even on a Redis that cannot
// evict a key. The hold only guards against eviction, so it is dropped when
// Redis reports it cannot evict.
func TestM72RedisCannotEvict(t *testing.T) {
	cases := []struct {
		cfg  map[string]string
		want bool
	}{
		{map[string]string{"maxmemory": "0", "maxmemory-policy": "allkeys-lru"}, true},
		{map[string]string{"maxmemory": "104857600", "maxmemory-policy": "noeviction"}, true},
		{map[string]string{"maxmemory": "104857600", "maxmemory-policy": "allkeys-lru"}, false},
		{map[string]string{"maxmemory": "104857600", "maxmemory-policy": "volatile-ttl"}, false},
		{map[string]string{"maxmemory-policy": "noeviction"}, false}, // incomplete answer
		{map[string]string{"maxmemory": "0"}, false},
		{map[string]string{}, false},
		{map[string]string{"maxmemory": "", "maxmemory-policy": ""}, false},
	}
	for _, c := range cases {
		if got := redisCannotEvict(c.cfg); got != c.want {
			t.Errorf("redisCannotEvict(%v) = %v, want %v", c.cfg, got, c.want)
		}
	}
}

// Codex M72 eviction R2 Low-1: the re-probe interval is measured on the
// monotonic clock, so a wall-clock step back cannot postpone it.
func TestM72ProbeIntervalIsMonotonic(t *testing.T) {
	s := &redisScanStatusStore{}
	s.probeAt.Store(monoNow() - int64(evictionProbeEvery) - 1)
	if !s.probeDue() {
		t.Fatal("probe not due after the interval")
	}
	s.probeAt.Store(monoNow())
	if s.probeDue() {
		t.Fatal("probe due right after one")
	}
}

// Codex M72 eviction R3 Medium-1: a key created under the holding scripts
// may stand for an eviction; when a later probe finds Redis can no longer
// evict, the holding scripts stay in use for one young span, so such a key
// cannot publish completed before its evicted runs could have rejoined. The
// first probe (at startup) applies at once.
func TestM72NoEvictTransitionKeepsHoldingForOneSpan(t *testing.T) {
	hold, imm := &statusScripts{}, &statusScripts{}
	s := &redisScanStatusStore{scripts: hold, immediate: imm}
	s.setNoEvict(true, true)
	if s.sc() != imm {
		t.Fatal("initial no-eviction probe: holding scripts, want immediate")
	}
	s.setNoEvict(false, false)
	if s.sc() != hold {
		t.Fatal("eviction possible: immediate scripts, want holding")
	}
	s.setNoEvict(true, false)
	if s.sc() != hold {
		t.Fatal("right after Redis stopped evicting: immediate scripts, want holding for one span")
	}
	s.immediateFrom.Store(monoNow() - 1)
	if s.sc() != imm {
		t.Fatal("after the span: holding scripts, want immediate")
	}
	s.setNoEvict(true, false) // unchanged answer: no new grace
	if s.sc() != imm {
		t.Fatal("a repeated no-eviction answer restarted the grace")
	}
}
