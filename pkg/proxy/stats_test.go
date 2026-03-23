package proxy

import (
	"encoding/json"
	"net/http/httptest"
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
