package proxy

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStats_RecordAllowed(t *testing.T) {
	s := NewStats()
	s.RecordAllowed("team-a")
	s.RecordAllowed("team-a")
	s.RecordAllowed("team-b")

	resp := s.ToResponse()
	if resp.TotalRequests != 3 {
		t.Errorf("expected 3 total, got %d", resp.TotalRequests)
	}
	if resp.AllowedRequests != 3 {
		t.Errorf("expected 3 allowed, got %d", resp.AllowedRequests)
	}
	if resp.Tenants["team-a"].Allowed != 2 {
		t.Errorf("expected 2 for team-a, got %d", resp.Tenants["team-a"].Allowed)
	}
	if resp.Tenants["team-b"].Allowed != 1 {
		t.Errorf("expected 1 for team-b, got %d", resp.Tenants["team-b"].Allowed)
	}
}

func TestStats_RecordBlocked(t *testing.T) {
	s := NewStats()
	s.RecordBlocked("team-a", "prompt_injection")
	s.RecordBlocked("team-a", "prompt_injection")
	s.RecordBlocked("team-b", "blocked_pattern")

	resp := s.ToResponse()
	if resp.BlockedRequests != 3 {
		t.Errorf("expected 3 blocked, got %d", resp.BlockedRequests)
	}
	if resp.ViolationCounts["prompt_injection"] != 2 {
		t.Errorf("expected 2 injection violations, got %d", resp.ViolationCounts["prompt_injection"])
	}
	if resp.ViolationCounts["blocked_pattern"] != 1 {
		t.Errorf("expected 1 blocked_pattern, got %d", resp.ViolationCounts["blocked_pattern"])
	}
}

func TestStats_RecordRateLimited(t *testing.T) {
	s := NewStats()
	s.RecordRateLimited("team-a")

	resp := s.ToResponse()
	if resp.RateLimited != 1 {
		t.Errorf("expected 1 rate limited, got %d", resp.RateLimited)
	}
	if resp.Tenants["team-a"].RateLimited != 1 {
		t.Errorf("expected 1 rate limited for team-a, got %d", resp.Tenants["team-a"].RateLimited)
	}
}

func TestStats_BlockRate(t *testing.T) {
	s := NewStats()
	s.RecordAllowed("team-a")
	s.RecordAllowed("team-a")
	s.RecordBlocked("team-a", "injection")
	s.RecordRateLimited("team-a")

	resp := s.ToResponse()
	// 1 blocked out of 4 total = 25%
	if resp.BlockRate < 24.9 || resp.BlockRate > 25.1 {
		t.Errorf("expected ~25%% block rate, got %.1f%%", resp.BlockRate)
	}
}

func TestStats_AnonymousTenant(t *testing.T) {
	s := NewStats()
	s.RecordAllowed("")

	resp := s.ToResponse()
	if _, ok := resp.Tenants["_anonymous"]; !ok {
		t.Error("expected _anonymous tenant for empty tenant header")
	}
}

func TestStats_Handler(t *testing.T) {
	s := NewStats()
	s.RecordAllowed("team-a")
	s.RecordBlocked("team-b", "injection")

	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/stats", nil))

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp StatsResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.TotalRequests != 2 {
		t.Errorf("expected 2 total in JSON, got %d", resp.TotalRequests)
	}
	if resp.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}

func TestStats_Uptime(t *testing.T) {
	s := NewStats()
	resp := s.ToResponse()
	if resp.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}

func TestStats_ZeroBlockRate(t *testing.T) {
	s := NewStats()
	resp := s.ToResponse()
	if resp.BlockRate != 0 {
		t.Errorf("expected 0 block rate with no requests, got %f", resp.BlockRate)
	}
}

func TestStats_AuditStream_OmittedWhenNoBrokerWired(t *testing.T) {
	s := NewStats()
	resp := s.ToResponse()
	if resp.AuditStream != nil {
		t.Errorf("expected nil AuditStream with no broker wired, got %+v", resp.AuditStream)
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "audit_stream") {
		t.Errorf("expected audit_stream key omitted from JSON, got %s", data)
	}
}

func TestStats_AuditStream_ReflectsBroker(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()
	s := NewStats().WithAuditBroker(b)

	sub := b.Subscribe(1)
	b.Publish(AuditEvent{Tenant: "t1"}) // fills buffer
	b.Publish(AuditEvent{Tenant: "t1"}) // overflows: 1 drop
	_ = sub

	resp := s.ToResponse()
	if resp.AuditStream == nil {
		t.Fatal("expected non-nil AuditStream once a broker is wired")
	}
	if resp.AuditStream.Subscribers != 1 {
		t.Errorf("want 1 subscriber, got %d", resp.AuditStream.Subscribers)
	}
	if resp.AuditStream.TotalDropped != 1 {
		t.Errorf("want 1 total dropped, got %d", resp.AuditStream.TotalDropped)
	}
}

func TestStats_WithAuditBroker_NilIsNoop(t *testing.T) {
	s := NewStats()
	s.WithAuditBroker(nil)
	resp := s.ToResponse()
	if resp.AuditStream != nil {
		t.Errorf("WithAuditBroker(nil) must not wire a probe, got %+v", resp.AuditStream)
	}
}

// TestStats_TenantCapBoundsMemoryAndRoutesToOverflow pins the fix for
// a real DoS: X-Tenant is client-asserted, so an attacker sending N
// unique tenant headers could grow tenantStats without bound and OOM
// the proxy. The cap routes overflow into a shared OverflowTenant
// entry rather than growing the map, and increments TenantOverflows
// so cap-firing is visible on /stats instead of silent — silent
// eviction is what nobody notices until an incident timeline is
// being read.
func TestStats_TenantCapBoundsMemoryAndRoutesToOverflow(t *testing.T) {
	s := NewStats().WithMaxTenants(3)

	// First 3 distinct tenants land in their own entries.
	s.RecordAllowed("alpha")
	s.RecordAllowed("bravo")
	s.RecordAllowed("charlie")

	// 4th and 5th distinct tenants must NOT create new entries — they
	// route into the shared OverflowTenant entry.
	s.RecordAllowed("delta")
	s.RecordBlocked("echo", "prompt_injection")

	resp := s.ToResponse()

	// Overflow tenant must exist and carry both routed events.
	ov, ok := resp.Tenants[OverflowTenant]
	if !ok {
		t.Fatalf("OverflowTenant %q missing from response; got tenants=%v", OverflowTenant, resp.Tenants)
	}
	if ov.Allowed != 1 || ov.Blocked != 1 {
		t.Errorf("OverflowTenant should aggregate the 4th allowed + 5th blocked, got allowed=%d blocked=%d", ov.Allowed, ov.Blocked)
	}

	// TenantOverflows counter reflects both cap-firings so operators
	// see the signal on /stats.
	if resp.TenantOverflows != 2 {
		t.Errorf("TenantOverflows should be 2 (one per cap-fire), got %d", resp.TenantOverflows)
	}

	// Original three tenants are untouched — no LRU eviction robbed
	// them of state because of attacker-controlled cardinality.
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if resp.Tenants[name].Allowed != 1 {
			t.Errorf("tenant %q must retain its Allowed=1 (cap-then-overflow does NOT evict existing), got %+v", name, resp.Tenants[name])
		}
	}

	// Map size is bounded at maxTenants + 1 (the +1 is the overflow
	// entry itself); it does NOT keep growing with additional distinct
	// tenants beyond the cap.
	if len(resp.Tenants) != 4 { // alpha bravo charlie + _overflow
		t.Errorf("tenants map must be bounded at maxTenants+1=4, got %d entries: %v", len(resp.Tenants), resp.Tenants)
	}

	// Another 100 unique attacker-cardinality tenants must not grow
	// the map further — the cap holds regardless of how much traffic
	// hits it.
	for i := 0; i < 100; i++ {
		s.RecordAllowed(fmt.Sprintf("attacker-%d", i))
	}
	resp = s.ToResponse()
	if len(resp.Tenants) != 4 {
		t.Errorf("map grew under 100 attacker tenants — cap not enforced; got %d entries", len(resp.Tenants))
	}
	if resp.TenantOverflows != 102 {
		t.Errorf("TenantOverflows should be 2 (original) + 100 (attackers) = 102, got %d", resp.TenantOverflows)
	}
}
