package proxy

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxTenants caps the distinct-tenant cardinality of Stats and
// TokenBucket so an attacker sending random X-Tenant headers cannot
// grow either map without bound (real DoS shape — X-Tenant is
// client-asserted so the map key is attacker-controlled). Chosen
// comfortably above any plausible legitimate tenant count: a modelgate
// serving 4096 distinct authenticated tenants is a scale nobody in
// this stack's deployment topology has reached; the cap is defence
// against pathological cardinality, not tuning for realistic growth.
//
// See getTenantStats and TokenBucket.getOrCreateLocked for the
// cap-then-overflow policy (rather than LRU eviction, which would let
// an attacker evict a legitimate tenant's TokenBucket and hand them a
// freshly-refilled bucket — making the DoS attack the cheaper path,
// not the more expensive one).
const DefaultMaxTenants = 4096

// OverflowTenant is the shared tenant key used when the distinct-
// tenant cap is reached. All overflow requests attribute to this key,
// so operators watching /stats can see tenantOverflows count as a
// signal that either legitimate growth exceeded the cap (raise it) or
// pathological cardinality is happening (mitigate upstream). The key
// is visible in StatsResponse.Tenants and in gpudab's per-tenant view.
const OverflowTenant = "_overflow"

// Stats tracks live request statistics for the proxy.
type Stats struct {
	mu sync.RWMutex

	StartedAt       time.Time
	TotalRequests   atomic.Int64
	AllowedRequests atomic.Int64
	BlockedRequests atomic.Int64
	RateLimited     atomic.Int64

	// TenantOverflows counts requests routed to the shared OverflowTenant
	// bucket because the distinct-tenant cap was reached. Silently
	// evicting is what nobody notices until they read an incident
	// timeline — this counter is what makes cap-firing visible.
	TenantOverflows atomic.Int64

	// maxTenants caps the size of tenantStats; 0 means unbounded (only
	// used in tests that don't care about the cap). Default is
	// DefaultMaxTenants via NewStats.
	maxTenants int

	// Provider identity (e.g. "generic", "nim") — reported in /stats so
	// dashboards can tell which upstream is being proxied without having
	// to read the process flags.
	provider string
	backend  string

	// Per-tenant stats
	tenantStats map[string]*TenantStats

	// Per-rule violation counts
	violationCounts map[string]*atomic.Int64

	// audit is an optional AuditBroker probe so /stats can report
	// audit-stream health at the source, not just from a downstream
	// consumer's point of view. Nil when WithAuditBroker was never
	// called (e.g. tests that don't wire a broker).
	audit auditBrokerProbe

	// rateLimiter is an optional rate-limiter probe so /stats can
	// render its overflow count (attacker-cardinality signal) alongside
	// TenantOverflows. Nil when WithRateLimiter was never called.
	rateLimiter rateLimiterProbe
}

// auditBrokerProbe is the narrow read surface Stats needs from an
// AuditBroker. Satisfied by *AuditBroker; kept as an interface so tests
// can substitute a fake without spinning up subscriptions.
type auditBrokerProbe interface {
	Subscribers() int
	TotalDropped() int64
}

// rateLimiterProbe is the narrow read surface Stats needs from the
// rate limiter to render RateLimitOverflows on /stats. Satisfied by
// *security.TokenBucket via its Overflows() method; kept as an
// interface so this package doesn't import pkg/security.
type rateLimiterProbe interface {
	Overflows() int64
}

// AuditStreamStats is the /stats view of audit-stream broker health.
type AuditStreamStats struct {
	Subscribers  int   `json:"subscribers"`
	TotalDropped int64 `json:"total_dropped"`
}

// TenantStats tracks per-tenant usage.
type TenantStats struct {
	Allowed     atomic.Int64
	Blocked     atomic.Int64
	RateLimited atomic.Int64
}

// StatsResponse is the JSON response from /stats.
//
// TenantOverflows and RateLimitOverflows are the visibility surface
// for the cap-then-overflow policy on distinct-tenant cardinality.
// Non-zero values mean requests hit the shared OverflowTenant entry
// because the distinct-tenant map reached its cap — either legitimate
// growth exceeded the cap and it should be raised, or pathological
// cardinality is happening and it should be mitigated upstream.
// Silent eviction/overflow is what nobody notices until an incident
// timeline gets read; these counters make it non-silent.
type StatsResponse struct {
	Uptime             string                     `json:"uptime"`
	Provider           string                     `json:"provider,omitempty"`
	Backend            string                     `json:"backend,omitempty"`
	TotalRequests      int64                      `json:"total_requests"`
	AllowedRequests    int64                      `json:"allowed_requests"`
	BlockedRequests    int64                      `json:"blocked_requests"`
	RateLimited        int64                      `json:"rate_limited"`
	BlockRate          float64                    `json:"block_rate_percent"`
	TenantOverflows    int64                      `json:"tenant_overflows"`
	RateLimitOverflows int64                      `json:"rate_limit_overflows"`
	Tenants            map[string]TenantStatsJSON `json:"tenants"`
	ViolationCounts    map[string]int64           `json:"violation_counts"`
	AuditStream        *AuditStreamStats          `json:"audit_stream,omitempty"`
}

// TenantStatsJSON is the per-tenant JSON shape.
type TenantStatsJSON struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	RateLimited int64 `json:"rate_limited"`
}

// NewStats creates a new stats tracker with the default per-tenant cap.
// Use WithMaxTenants to change the cap (0 disables it — tests only).
func NewStats() *Stats {
	return &Stats{
		StartedAt:       time.Now(),
		tenantStats:     make(map[string]*TenantStats),
		violationCounts: make(map[string]*atomic.Int64),
		maxTenants:      DefaultMaxTenants,
	}
}

// WithMaxTenants tunes the distinct-tenant cap. Pass 0 to disable the
// cap (only sensible in tests that pre-populate a known set). Returns
// the receiver so callers can chain from NewStats.
func (s *Stats) WithMaxTenants(n int) *Stats {
	s.mu.Lock()
	s.maxTenants = n
	s.mu.Unlock()
	return s
}

// WithAuditBroker registers the process's AuditBroker so /stats exposes
// its subscriber count and lifetime dropped-event total. Pass nil (or
// never call this) to leave the field omitted. Returns the receiver so
// callers can chain from NewStats.
func (s *Stats) WithAuditBroker(broker auditBrokerProbe) *Stats {
	if broker != nil {
		s.mu.Lock()
		s.audit = broker
		s.mu.Unlock()
	}
	return s
}

// WithRateLimiter registers the process's rate limiter so /stats
// exposes its distinct-tenant overflow count. Pass nil (or never call
// this) to leave the field zero. Returns the receiver for chaining.
func (s *Stats) WithRateLimiter(rl rateLimiterProbe) *Stats {
	if rl != nil {
		s.mu.Lock()
		s.rateLimiter = rl
		s.mu.Unlock()
	}
	return s
}

// SetProvider records which upstream provider is being proxied so the
// value appears in /stats responses. Safe to call once at startup.
func (s *Stats) SetProvider(name, backend string) {
	s.mu.Lock()
	s.provider = name
	s.backend = backend
	s.mu.Unlock()
}

// RecordAllowed records a successful request.
func (s *Stats) RecordAllowed(tenant string) {
	s.TotalRequests.Add(1)
	s.AllowedRequests.Add(1)
	s.getTenantStats(tenant).Allowed.Add(1)
}

// RecordBlocked records a blocked request with the violation rule.
func (s *Stats) RecordBlocked(tenant, rule string) {
	s.TotalRequests.Add(1)
	s.BlockedRequests.Add(1)
	s.getTenantStats(tenant).Blocked.Add(1)
	s.getViolationCounter(rule).Add(1)
}

// RecordRateLimited records a rate-limited request.
func (s *Stats) RecordRateLimited(tenant string) {
	s.TotalRequests.Add(1)
	s.RateLimited.Add(1)
	s.getTenantStats(tenant).RateLimited.Add(1)
	s.getViolationCounter("rate_limited").Add(1)
}

func (s *Stats) getTenantStats(tenant string) *TenantStats {
	if tenant == "" {
		tenant = "_anonymous"
	}
	s.mu.RLock()
	ts, ok := s.tenantStats[tenant]
	s.mu.RUnlock()
	if ok {
		return ts
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check after acquiring write lock
	if ts, ok = s.tenantStats[tenant]; ok {
		return ts
	}
	// Cap enforcement: when the distinct-tenant map hits maxTenants,
	// route all subsequent unseen tenants into a single OverflowTenant
	// entry rather than growing the map. Cap-then-overflow is chosen
	// over LRU-eviction because LRU would let an attacker evict a
	// legitimate tenant's TenantStats — losing that tenant's real
	// counters as a side effect of attacker-controlled cardinality —
	// while overflow-sharing means the attacker's fake tenants all
	// collapse into one entry that has no bearing on any real tenant's
	// state. Increment TenantOverflows so the cap-firing is visible on
	// /stats rather than silent.
	if s.maxTenants > 0 && len(s.tenantStats) >= s.maxTenants && tenant != OverflowTenant {
		s.TenantOverflows.Add(1)
		ov, ok := s.tenantStats[OverflowTenant]
		if !ok {
			ov = &TenantStats{}
			s.tenantStats[OverflowTenant] = ov
		}
		return ov
	}
	ts = &TenantStats{}
	s.tenantStats[tenant] = ts
	return ts
}

func (s *Stats) getViolationCounter(rule string) *atomic.Int64 {
	s.mu.RLock()
	c, ok := s.violationCounts[rule]
	s.mu.RUnlock()
	if ok {
		return c
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok = s.violationCounts[rule]; ok {
		return c
	}
	c = &atomic.Int64{}
	s.violationCounts[rule] = c
	return c
}

// ToResponse builds the JSON response.
func (s *Stats) ToResponse() StatsResponse {
	total := s.TotalRequests.Load()
	blocked := s.BlockedRequests.Load()

	var blockRate float64
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
	}

	tenants := make(map[string]TenantStatsJSON)
	s.mu.RLock()
	for name, ts := range s.tenantStats {
		tenants[name] = TenantStatsJSON{
			Allowed:     ts.Allowed.Load(),
			Blocked:     ts.Blocked.Load(),
			RateLimited: ts.RateLimited.Load(),
		}
	}

	violations := make(map[string]int64)
	for rule, c := range s.violationCounts {
		violations[rule] = c.Load()
	}
	provider := s.provider
	backend := s.backend
	audit := s.audit
	rl := s.rateLimiter
	s.mu.RUnlock()

	var auditStream *AuditStreamStats
	if audit != nil {
		auditStream = &AuditStreamStats{
			Subscribers:  audit.Subscribers(),
			TotalDropped: audit.TotalDropped(),
		}
	}

	var rateLimitOverflows int64
	if rl != nil {
		rateLimitOverflows = rl.Overflows()
	}

	return StatsResponse{
		Uptime:             time.Since(s.StartedAt).Round(time.Second).String(),
		Provider:           provider,
		Backend:            backend,
		TotalRequests:      total,
		AllowedRequests:    s.AllowedRequests.Load(),
		BlockedRequests:    blocked,
		RateLimited:        s.RateLimited.Load(),
		BlockRate:          blockRate,
		TenantOverflows:    s.TenantOverflows.Load(),
		RateLimitOverflows: rateLimitOverflows,
		Tenants:            tenants,
		ViolationCounts:    violations,
		AuditStream:        auditStream,
	}
}

// Handler returns an HTTP handler for the /stats endpoint.
func (s *Stats) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.ToResponse())
	}
}
