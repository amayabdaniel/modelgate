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

	b, ok := tb.buckets[tenant]
	if !ok {
		b = &bucket{
			tokens:   tb.capacity,
			lastFill: time.Now(),
		}
		tb.buckets[tenant] = b
	}

	// Refill based on elapsed time
	elapsed := time.Since(b.lastFill)
	refill := int(elapsed.Minutes()) * tb.rate
	if refill > 0 {
		b.tokens += refill
		if b.tokens > tb.capacity {
			b.tokens = tb.capacity
		}
		b.lastFill = time.Now()
	}

	if b.tokens >= tokens {
		b.tokens -= tokens
		return true
	}

	return false
}

// Remaining returns the number of tokens remaining for a tenant.
func (tb *TokenBucket) Remaining(tenant string) int {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	b, ok := tb.buckets[tenant]
	if !ok {
		return tb.capacity
	}
	return b.tokens
}

// Reset clears the rate limiter state for a tenant.
func (tb *TokenBucket) Reset(tenant string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	delete(tb.buckets, tenant)
}
