package proxy

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks live request statistics for the proxy.
type Stats struct {
	mu sync.RWMutex

	StartedAt  time.Time
	TotalRequests    atomic.Int64
	AllowedRequests  atomic.Int64
	BlockedRequests  atomic.Int64
	RateLimited      atomic.Int64

	// Per-tenant stats
	tenantStats map[string]*TenantStats

	// Per-rule violation counts
	violationCounts map[string]*atomic.Int64
}

// TenantStats tracks per-tenant usage.
type TenantStats struct {
	Allowed     atomic.Int64
	Blocked     atomic.Int64
	RateLimited atomic.Int64
}

// StatsResponse is the JSON response from /stats.
type StatsResponse struct {
	Uptime           string                       `json:"uptime"`
	TotalRequests    int64                        `json:"total_requests"`
	AllowedRequests  int64                        `json:"allowed_requests"`
	BlockedRequests  int64                        `json:"blocked_requests"`
	RateLimited      int64                        `json:"rate_limited"`
	BlockRate        float64                      `json:"block_rate_percent"`
	Tenants          map[string]TenantStatsJSON   `json:"tenants"`
	ViolationCounts  map[string]int64             `json:"violation_counts"`
}

// TenantStatsJSON is the per-tenant JSON shape.
type TenantStatsJSON struct {
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	RateLimited int64 `json:"rate_limited"`
}

// NewStats creates a new stats tracker.
func NewStats() *Stats {
	return &Stats{
		StartedAt:       time.Now(),
		tenantStats:     make(map[string]*TenantStats),
		violationCounts: make(map[string]*atomic.Int64),
	}
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
	s.mu.RUnlock()

	return StatsResponse{
		Uptime:          time.Since(s.StartedAt).Round(time.Second).String(),
		TotalRequests:   total,
		AllowedRequests: s.AllowedRequests.Load(),
		BlockedRequests: blocked,
		RateLimited:     s.RateLimited.Load(),
		BlockRate:       blockRate,
		Tenants:         tenants,
		ViolationCounts: violations,
	}
}

// Handler returns an HTTP handler for the /stats endpoint.
func (s *Stats) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.ToResponse())
	}
}
