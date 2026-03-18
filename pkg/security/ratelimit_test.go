package security

import "testing"

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
