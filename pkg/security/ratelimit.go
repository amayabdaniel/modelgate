package security

import (
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxTenants caps the distinct-tenant cardinality of a
// TokenBucket so an attacker sending random X-Tenant headers can't
// grow the buckets map without bound. See getOrCreateLocked for the
// cap-then-overflow policy (chosen over LRU eviction, which would
// have let an attacker evict a legitimate tenant's bucket and hand
// them a freshly-refilled one — making the DoS attack the cheaper
// path, not the more expensive one). Same value and reasoning as
// proxy.DefaultMaxTenants; not imported to avoid a cycle
// (proxy → security → proxy would loop).
const DefaultMaxTenants = 4096

// OverflowTenant is the shared bucket key used when the distinct-
// tenant cap is reached. Rate-limit budget across every overflow
// tenant collapses to this one bucket, so an attacker's fake tenants
// rate-limit each other and can't cheaply obtain fresh per-tenant
// budgets by cycling names.
const OverflowTenant = "_overflow"

// TokenBucket implements a per-tenant token bucket rate limiter.
type TokenBucket struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int // tokens per refill
	interval time.Duration
	capacity int

	// maxTenants caps the size of buckets; 0 disables the cap (only
	// tests set it to 0). Default is DefaultMaxTenants via NewTokenBucket.
	maxTenants int

	// overflows counts requests routed to the shared OverflowTenant
	// bucket because the cap was reached. Exposed via Overflows() so
	// /stats can render it — see proxy.StatsResponse.RateLimitOverflows.
	overflows atomic.Int64
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// NewTokenBucket creates a rate limiter that refills at the given rate
// per interval, with the default distinct-tenant cap. Use
// WithMaxTenants to change the cap (0 disables it — tests only).
func NewTokenBucket(tokensPerMinute, burstCapacity int) *TokenBucket {
	return &TokenBucket{
		buckets:    make(map[string]*bucket),
		rate:       tokensPerMinute,
		interval:   time.Minute,
		capacity:   burstCapacity,
		maxTenants: DefaultMaxTenants,
	}
}

// WithMaxTenants tunes the distinct-tenant cap. Pass 0 to disable
// (only sensible in tests). Returns the receiver for chaining.
func (tb *TokenBucket) WithMaxTenants(n int) *TokenBucket {
	tb.mu.Lock()
	tb.maxTenants = n
	tb.mu.Unlock()
	return tb
}

// Overflows returns the running count of Allow calls that fell into
// the shared OverflowTenant bucket because the distinct-tenant cap
// was reached. Exposed on /stats as RateLimitOverflows.
func (tb *TokenBucket) Overflows() int64 { return tb.overflows.Load() }

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
//
// When the distinct-tenant cap is reached (see DefaultMaxTenants),
// subsequent unseen tenants share a single OverflowTenant bucket
// rather than growing the map. The design deliberately favours the
// attacker's cost over the defender's convenience: all overflow
// tenants rate-limit each other through one bucket, so an attacker
// who cycles fake tenants gets a shared budget instead of a fresh
// per-tenant one — the opposite of what LRU eviction would give them.
// Existing legitimate tenants stay in the map unchanged; the cap
// affects only the ability to allocate new distinct entries.
func (tb *TokenBucket) getOrCreateLocked(tenant string) *bucket {
	if b, ok := tb.buckets[tenant]; ok {
		return b
	}
	if tb.maxTenants > 0 && len(tb.buckets) >= tb.maxTenants && tenant != OverflowTenant {
		tb.overflows.Add(1)
		if ov, ok := tb.buckets[OverflowTenant]; ok {
			return ov
		}
		ov := &bucket{tokens: tb.capacity, lastFill: time.Now()}
		tb.buckets[OverflowTenant] = ov
		return ov
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
