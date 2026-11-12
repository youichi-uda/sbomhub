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
