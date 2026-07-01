package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestBackoffPolicy_Delay_NoJitter(t *testing.T) {
	p := BackoffPolicy{
		MaxRetries:   5,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Jitter:       false,
	}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 100 * time.Millisecond},
		{1, 200 * time.Millisecond},
		{2, 400 * time.Millisecond},
		{3, 800 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("attempt=%d", tc.attempt), func(t *testing.T) {
			got := p.Delay(tc.attempt)
			if got != tc.want {
				t.Errorf("Delay(%d) = %v, want %v", tc.attempt, got, tc.want)
			}
		})
	}
}

func TestBackoffPolicy_Delay_CapsAtMaxDelay(t *testing.T) {
	p := BackoffPolicy{
		MaxRetries:   10,
		InitialDelay: 1 * time.Second,
		MaxDelay:     4 * time.Second,
		Jitter:       false,
	}
	// attempt=3 would be 8s without a cap; cap must clamp to 4s.
	got := p.Delay(3)
	if got != 4*time.Second {
		t.Errorf("Delay(3) = %v, want capped at 4s", got)
	}
	// attempt=10 stays capped (no overflow).
	got = p.Delay(10)
	if got != 4*time.Second {
		t.Errorf("Delay(10) = %v, want capped at 4s", got)
	}
}

func TestBackoffPolicy_Delay_ZeroInitialShortCircuits(t *testing.T) {
	p := BackoffPolicy{MaxRetries: 3, InitialDelay: 0, MaxDelay: time.Second, Jitter: true}
	if got := p.Delay(0); got != 0 {
		t.Errorf("Delay(0) with zero InitialDelay = %v, want 0", got)
	}
	if got := p.Delay(5); got != 0 {
		t.Errorf("Delay(5) with zero InitialDelay = %v, want 0", got)
	}
}

func TestBackoffPolicy_Delay_JitterWithinBound(t *testing.T) {
	p := BackoffPolicy{
		MaxRetries:   5,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     10 * time.Second,
		Jitter:       true,
	}
	// Full jitter must stay in [0, unjittered] — probe 100 times to catch
	// wrap-around bugs.
	unjittered := 200 * time.Millisecond // attempt=1
	for i := 0; i < 100; i++ {
		got := p.Delay(1)
		if got < 0 || got > unjittered {
			t.Fatalf("Delay(1) with jitter = %v, want in [0, %v]", got, unjittered)
		}
	}
}

func TestBackoffPolicy_Delay_NegativeAttemptClamped(t *testing.T) {
	p := BackoffPolicy{MaxRetries: 3, InitialDelay: 100 * time.Millisecond, MaxDelay: time.Second, Jitter: false}
	got := p.Delay(-5)
	if got != 100*time.Millisecond {
		t.Errorf("Delay(-5) = %v, want treated as attempt=0 (100ms)", got)
	}
}

func TestRespectRetryAfter_Seconds(t *testing.T) {
	got := RespectRetryAfter("5", 42*time.Second)
	if got != 5*time.Second {
		t.Errorf("RespectRetryAfter(\"5\") = %v, want 5s", got)
	}
}

func TestRespectRetryAfter_Zero(t *testing.T) {
	got := RespectRetryAfter("0", 42*time.Second)
	if got != 0 {
		t.Errorf("RespectRetryAfter(\"0\") = %v, want 0", got)
	}
}

func TestRespectRetryAfter_NegativeClampsToZero(t *testing.T) {
	got := RespectRetryAfter("-3", 42*time.Second)
	if got != 0 {
		t.Errorf("RespectRetryAfter(\"-3\") = %v, want 0 (past)", got)
	}
}

func TestRespectRetryAfter_HTTPDateFuture(t *testing.T) {
	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	got := RespectRetryAfter(future, 42*time.Second)
	// Allow a generous window because time.Until races with test scheduling.
	if got <= 0 || got > 4*time.Second {
		t.Errorf("RespectRetryAfter(future HTTP-date) = %v, want ~3s", got)
	}
}

func TestRespectRetryAfter_HTTPDatePast(t *testing.T) {
	past := time.Now().Add(-3 * time.Second).UTC().Format(http.TimeFormat)
	got := RespectRetryAfter(past, 42*time.Second)
	if got != 0 {
		t.Errorf("RespectRetryAfter(past HTTP-date) = %v, want 0", got)
	}
}

func TestRespectRetryAfter_Malformed(t *testing.T) {
	cases := []string{"", "  ", "not-a-number", "banana"}
	for _, c := range cases {
		t.Run(fmt.Sprintf("input=%q", c), func(t *testing.T) {
			got := RespectRetryAfter(c, 42*time.Second)
			if got != 42*time.Second {
				t.Errorf("RespectRetryAfter(%q) = %v, want fallback 42s", c, got)
			}
		})
	}
}

// TestRespectRetryAfter_OverflowClamped_F295 pins the F295 defence: a
// syntactically valid but absurdly large delta-seconds value must not
// overflow time.Duration into a negative / near-zero wait. Prior to F295
// the delta-seconds path used strconv.Atoi + direct * time.Second, so
// e.g. "9999999999999" would wrap. After F295 the value is clamped to
// maxRetryAfterSeconds (~292 years) before the * time.Second conversion.
func TestRespectRetryAfter_OverflowClamped_F295(t *testing.T) {
	// int64-max seconds — the largest thing strconv.ParseInt can accept.
	// Without the F295 clamp the * time.Second would overflow into a
	// negative time.Duration and waitOrDone would skip the wait entirely.
	got := RespectRetryAfter("9223372036854775807", 42*time.Second)
	if got <= 0 {
		t.Fatalf("RespectRetryAfter(int64-max) = %v, want positive (clamp, "+
			"not overflow wrap)", got)
	}
	// Sanity: an absurdly large "9999999999999" is well past maxRetryAfterSeconds
	// and must also come out positive (clamped, not wrapped).
	got = RespectRetryAfter("9999999999999", 42*time.Second)
	if got <= 0 {
		t.Fatalf("RespectRetryAfter(9999999999999) = %v, want positive", got)
	}
}

// TestRespectRetryAfter_ParseIntBoundary_F295 pins that the migration from
// strconv.Atoi to strconv.ParseInt(_, 10, 64) does not regress the small /
// legitimate delta-seconds values — headers within any realistic provider
// window still map to exact durations.
func TestRespectRetryAfter_ParseIntBoundary_F295(t *testing.T) {
	// Small legitimate values still map cleanly (this is what all real
	// providers send).
	if got := RespectRetryAfter("30", 42*time.Second); got != 30*time.Second {
		t.Errorf("RespectRetryAfter(30) = %v, want 30s", got)
	}
	// A value that would overflow a 32-bit Atoi on a 32-bit target but
	// fits in int64 is now accepted rather than falling through to the
	// HTTP-date parse branch.
	if got := RespectRetryAfter("3000000000", 42*time.Second); got <= 0 {
		t.Errorf("RespectRetryAfter(3000000000) = %v, want positive "+
			"(int64 parse, not Atoi failure)", got)
	}
}

// TestRespectRateLimitReset_FarFutureClamped_F295 pins the sibling clamp
// on the X-RateLimit-Reset helper: an absurdly large future epoch must
// not produce a wait beyond time.Duration's representable range.
func TestRespectRateLimitReset_FarFutureClamped_F295(t *testing.T) {
	// int64-max epoch — well past any legitimate reset.
	got := RespectRateLimitReset("9223372036854775807", 42*time.Second)
	if got <= 0 {
		t.Fatalf("RespectRateLimitReset(int64-max) = %v, want positive "+
			"(clamp, not overflow wrap)", got)
	}
}

func TestRespectRateLimitReset_Future(t *testing.T) {
	future := time.Now().Add(4 * time.Second).Unix()
	got := RespectRateLimitReset(fmt.Sprintf("%d", future), 42*time.Second)
	if got <= 0 || got > 5*time.Second {
		t.Errorf("RespectRateLimitReset(future epoch) = %v, want ~4s", got)
	}
}

func TestRespectRateLimitReset_Past(t *testing.T) {
	past := time.Now().Add(-4 * time.Second).Unix()
	got := RespectRateLimitReset(fmt.Sprintf("%d", past), 42*time.Second)
	if got != 0 {
		t.Errorf("RespectRateLimitReset(past epoch) = %v, want 0", got)
	}
}

func TestRespectRateLimitReset_Malformed(t *testing.T) {
	if got := RespectRateLimitReset("", 42*time.Second); got != 42*time.Second {
		t.Errorf("RespectRateLimitReset(empty) = %v, want fallback", got)
	}
	if got := RespectRateLimitReset("banana", 42*time.Second); got != 42*time.Second {
		t.Errorf("RespectRateLimitReset(malformed) = %v, want fallback", got)
	}
}

func TestWaitOrDone_CompletesAfterDelay(t *testing.T) {
	start := time.Now()
	err := waitOrDone(context.Background(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("waitOrDone: %v", err)
	}
	if time.Since(start) < 15*time.Millisecond {
		t.Errorf("waitOrDone returned too fast: %v", time.Since(start))
	}
}

func TestWaitOrDone_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := waitOrDone(ctx, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitOrDone err = %v, want context.Canceled", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Errorf("waitOrDone did not abort promptly: %v", time.Since(start))
	}
}

func TestWaitOrDone_ZeroDelayContextChecked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitOrDone(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("waitOrDone(cancelled, 0) = %v, want context.Canceled", err)
	}
	if err := waitOrDone(context.Background(), 0); err != nil {
		t.Errorf("waitOrDone(bg, 0) = %v, want nil", err)
	}
}

func TestDefaultBackoffPolicy(t *testing.T) {
	p := DefaultBackoffPolicy()
	if p.MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", p.MaxRetries)
	}
	if p.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay = %v, want 1s", p.InitialDelay)
	}
	if p.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", p.MaxDelay)
	}
	if !p.Jitter {
		t.Error("Jitter = false, want true")
	}
}
