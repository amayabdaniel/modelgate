package security

import (
	"testing"
	"time"
)

func TestTokenBucket_AllowWithinLimit(t *testing.T) {
	tb := NewTokenBucket(1000, 5000)

	if !tb.Allow("team-a", 100) {
		t.Error("should allow 100 tokens within capacity")
	}
	if !tb.Allow("team-a", 100) {
		t.Error("should allow another 100 tokens")
	}
}

func TestTokenBucket_BlocksOverLimit(t *testing.T) {
	tb := NewTokenBucket(1000, 500)

	if !tb.Allow("team-a", 400) {
		t.Error("should allow 400 tokens")
	}
	if tb.Allow("team-a", 200) {
		t.Error("should block — only 100 tokens remaining")
	}
}

func TestTokenBucket_IsolatesTenants(t *testing.T) {
	tb := NewTokenBucket(1000, 500)

	tb.Allow("team-a", 450)

	// team-b should have full capacity
	if !tb.Allow("team-b", 500) {
		t.Error("team-b should have independent budget")
	}

	// team-a should be near limit
	if tb.Allow("team-a", 100) {
		t.Error("team-a should be blocked — only 50 tokens left")
	}
}

func TestTokenBucket_Remaining(t *testing.T) {
	tb := NewTokenBucket(1000, 1000)

	if rem := tb.Remaining("new-tenant"); rem != 1000 {
		t.Errorf("new tenant should have full capacity, got %d", rem)
	}

	tb.Allow("new-tenant", 300)
	if rem := tb.Remaining("new-tenant"); rem != 700 {
		t.Errorf("expected 700 remaining, got %d", rem)
	}
}

func TestTokenBucket_Reset(t *testing.T) {
	tb := NewTokenBucket(1000, 1000)

	tb.Allow("team-a", 900)
	if rem := tb.Remaining("team-a"); rem != 100 {
		t.Errorf("expected 100 remaining before reset, got %d", rem)
	}

	tb.Reset("team-a")
	if rem := tb.Remaining("team-a"); rem != 1000 {
		t.Errorf("expected full capacity after reset, got %d", rem)
	}
}

func TestTokenBucket_ExactCapacity(t *testing.T) {
	tb := NewTokenBucket(1000, 500)

	if !tb.Allow("team-a", 500) {
		t.Error("should allow exactly capacity")
	}
	if tb.Allow("team-a", 1) {
		t.Error("should block at 0 tokens")
	}
}

func TestTokenBucket_ZeroTokenRequest(t *testing.T) {
	tb := NewTokenBucket(1000, 1000)

	if !tb.Allow("team-a", 0) {
		t.Error("zero token request should always be allowed")
	}
}

// TestTokenBucket_RefillPreservesSubIntervalRemainder guards against a
// regression where a refill snapped lastFill to time.Now() instead of
// advancing it by exactly the whole intervals just credited. That
// discarded the sub-interval remainder on every refill, so a tenant
// polling on a cadence that doesn't align to interval boundaries got
// refilled below the configured rate indefinitely (a 60/min config
// settling to an effective ~45/min at an 80s-every-other-check cadence).
//
// Uses a shrunk interval (1s instead of 1min) so the test runs fast; it
// drives lastFill directly (same-package access to the unexported
// bucket) rather than sleeping, so timing is exact and not flaky.
func TestTokenBucket_RefillPreservesSubIntervalRemainder(t *testing.T) {
	tb := NewTokenBucket(1, 100000) // 1 token/interval, capacity high enough to never cap
	tb.interval = time.Second

	b := &bucket{tokens: 0, lastFill: time.Now()}
	tb.mu.Lock()
	tb.buckets["team-a"] = b
	tb.mu.Unlock()

	// 1.4 intervals elapse: one whole interval refills 1 token; the 0.4
	// remainder must carry forward rather than being discarded.
	b.lastFill = time.Now().Add(-1400 * time.Millisecond)
	tb.Allow("team-a", 0)
	if got := tb.Remaining("team-a"); got != 1 {
		t.Fatalf("expected 1 token after 1.4 intervals, got %d", got)
	}

	// Only another 0.6 intervals pass on top of that 0.4 remainder — 1.0
	// total, so this alone should NOT be enough to refill again if the
	// remainder was discarded (buggy code would need a fresh 1.0 from
	// here since it snapped lastFill to "now" on the previous refill).
	// With the remainder correctly carried forward, 0.4 + 0.6 = 1.0
	// crosses exactly one more whole interval.
	b.lastFill = b.lastFill.Add(-600 * time.Millisecond)
	tb.Allow("team-a", 0)
	if got := tb.Remaining("team-a"); got != 2 {
		t.Fatalf("expected 2 tokens once the carried-forward remainder completes a whole interval, got %d (remainder was discarded)", got)
	}
}
