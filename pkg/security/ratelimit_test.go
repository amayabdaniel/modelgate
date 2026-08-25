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

// TestTokenBucket_RemainingRefillsWithoutAllow guards against a bug
// where Remaining returned the stored token count without crediting
// any refill that should have happened since the last Allow call.
// Callers polling Remaining (dashboards, admin surfaces, /v1/quota)
// would see values that only advanced when Allow itself ran — a
// tenant idle for hours would appear stuck at whatever token count
// was recorded on their last request.
//
// Uses the shrunk-interval / direct-manipulation pattern from
// TestTokenBucket_RefillPreservesSubIntervalRemainder so timing is
// exact and not flaky.
func TestTokenBucket_RemainingRefillsWithoutAllow(t *testing.T) {
	tb := NewTokenBucket(5, 100) // 5 tokens/interval, capacity 100
	tb.interval = time.Second

	// Seed: 3 tokens stored, lastFill "3 seconds ago" — 3 whole
	// intervals should have refilled 15 tokens without any Allow call.
	tb.mu.Lock()
	tb.buckets["team-a"] = &bucket{
		tokens:   3,
		lastFill: time.Now().Add(-3 * time.Second),
	}
	tb.mu.Unlock()

	got := tb.Remaining("team-a")
	if got != 18 { // 3 stored + 3 intervals * 5 tokens
		t.Errorf("Remaining must credit elapsed refills; want 18 (3 + 3*5), got %d", got)
	}

	// Second poll immediately after must be idempotent — no double
	// crediting from the same wall clock. lastFill was advanced by
	// exactly 3 seconds inside the first Remaining call.
	if again := tb.Remaining("team-a"); again != 18 {
		t.Errorf("second Remaining call must be idempotent, got %d", again)
	}
}

// TestTokenBucket_RemainingCapsAtCapacity ensures the refill inside
// Remaining honors the burst cap just like Allow does — a tenant idle
// for a long time cannot accumulate above capacity.
func TestTokenBucket_RemainingCapsAtCapacity(t *testing.T) {
	tb := NewTokenBucket(10, 25) // 10/interval, cap 25
	tb.interval = time.Second

	tb.mu.Lock()
	tb.buckets["team-a"] = &bucket{
		tokens:   0,
		lastFill: time.Now().Add(-1 * time.Hour), // way more than cap
	}
	tb.mu.Unlock()

	if got := tb.Remaining("team-a"); got != 25 {
		t.Errorf("Remaining refill must cap at burst capacity; want 25, got %d", got)
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
