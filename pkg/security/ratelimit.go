package security

import (
	"sync"
	"time"
)

// TokenBucket implements a per-tenant token bucket rate limiter.
type TokenBucket struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int     // tokens per refill
	interval time.Duration
	capacity int
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// NewTokenBucket creates a rate limiter that refills at the given rate per interval.
func NewTokenBucket(tokensPerMinute, burstCapacity int) *TokenBucket {
	return &TokenBucket{
		buckets:  make(map[string]*bucket),
		rate:     tokensPerMinute,
		interval: time.Minute,
		capacity: burstCapacity,
	}
}

// Allow checks if a tenant can consume the given number of tokens.
// Returns true if allowed, false if rate limited.
func (tb *TokenBucket) Allow(tenant string, tokens int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	b := tb.getOrCreateLocked(tenant)
	tb.refillLocked(b)

	if b.tokens >= tokens {
		b.tokens -= tokens
		return true
	}

	return false
}

// Remaining returns the number of tokens remaining for a tenant, after
// crediting any refill that should have happened since the last Allow
// call. Without this refill, callers polling Remaining (dashboards,
// admin surfaces, /v1/quota) would see stale values that only advance
// when Allow itself runs.
func (tb *TokenBucket) Remaining(tenant string) int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	b, ok := tb.buckets[tenant]
	if !ok {
		return tb.capacity
	}
	tb.refillLocked(b)
	return b.tokens
}

// getOrCreateLocked returns the bucket for tenant, allocating a
// full-capacity one if none exists. Caller must hold tb.mu.
func (tb *TokenBucket) getOrCreateLocked(tenant string) *bucket {
	if b, ok := tb.buckets[tenant]; ok {
		return b
	}
	b := &bucket{
		tokens:   tb.capacity,
		lastFill: time.Now(),
	}
	tb.buckets[tenant] = b
	return b
}

// refillLocked credits tokens for whole intervals elapsed since the
// last fill. lastFill advances by exactly the credited intervals (not
// time.Now()) so a sub-interval remainder carries over to the next
// check instead of being discarded — otherwise a tenant whose request
// cadence doesn't land on clean interval boundaries gets refilled
// below the configured rate indefinitely.
//
// Caller must hold tb.mu.
func (tb *TokenBucket) refillLocked(b *bucket) {
	elapsed := time.Since(b.lastFill)
	wholeIntervals := int(elapsed / tb.interval)
	if wholeIntervals <= 0 {
		return
	}
	b.tokens += wholeIntervals * tb.rate
	if b.tokens > tb.capacity {
		b.tokens = tb.capacity
	}
	b.lastFill = b.lastFill.Add(time.Duration(wholeIntervals) * tb.interval)
}

// Reset clears the rate limiter state for a tenant.
func (tb *TokenBucket) Reset(tenant string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	delete(tb.buckets, tenant)
}
