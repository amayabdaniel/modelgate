package security

import (
	"strings"
	"testing"
)

func TestPromptProfile_LearningPeriod(t *testing.T) {
	pp := NewPromptProfile(10)

	// During learning, nothing should be flagged
	for i := 0; i < 9; i++ {
		result := pp.Observe("team-a", "What is the weather today?")
		if result.IsAnomaly {
			t.Errorf("should not flag during learning period (sample %d)", i)
		}
	}
}

func TestPromptProfile_NormalPrompts(t *testing.T) {
	pp := NewPromptProfile(5)

	// Train with normal-length prompts
	for i := 0; i < 20; i++ {
		pp.Observe("team-a", "What is the weather today?")
	}

	// Similar prompt should not be flagged
	result := pp.Observe("team-a", "How is the weather tomorrow?")
	if result.IsAnomaly {
		t.Errorf("normal-length prompt should not be anomaly, score=%.2f", result.Score)
	}
}

func TestPromptProfile_DetectsLengthSpike(t *testing.T) {
	pp := NewPromptProfile(5)

	// Train with short prompts
	for i := 0; i < 20; i++ {
		pp.Observe("team-a", "Hello")
	}

	// Send a massive prompt
	longPrompt := strings.Repeat("This is a very long prompt that deviates significantly. ", 100)
	result := pp.Observe("team-a", longPrompt)

	if !result.IsAnomaly {
		t.Error("expected anomaly for massive prompt after short training")
	}
	if result.Score < 3.0 {
		t.Errorf("expected high z-score, got %.2f", result.Score)
	}
}

func TestPromptProfile_IsolatesTenants(t *testing.T) {
	pp := NewPromptProfile(5)

	// Team A sends short prompts
	for i := 0; i < 20; i++ {
		pp.Observe("team-a", "Hi")
	}

	// Team B sends long prompts
	for i := 0; i < 20; i++ {
		pp.Observe("team-b", strings.Repeat("Long prompt content here. ", 20))
	}

	// Long prompt from team-a should be anomalous
	result := pp.Observe("team-a", strings.Repeat("Long prompt content here. ", 20))
	if !result.IsAnomaly {
		t.Error("long prompt from short-prompt tenant should be anomalous")
	}

	// Same long prompt from team-b should be normal
	result = pp.Observe("team-b", strings.Repeat("Long prompt content here. ", 20))
	if result.IsAnomaly {
		t.Error("normal-length prompt for team-b should not be anomalous")
	}
}

func TestPromptProfile_TenantStats(t *testing.T) {
	pp := NewPromptProfile(5)

	for i := 0; i < 10; i++ {
		pp.Observe("team-a", "Hello world")
	}

	count, mean, stddev := pp.TenantStats("team-a")
	if count != 10 {
		t.Errorf("expected 10 samples, got %d", count)
	}
	if mean != 11 { // "Hello world" = 11 chars
		t.Errorf("expected mean ~11, got %.0f", mean)
	}
	if stddev != 0 { // all same length
		t.Errorf("expected stddev 0 for uniform prompts, got %.1f", stddev)
	}
}

func TestPromptProfile_UnknownTenant(t *testing.T) {
	pp := NewPromptProfile(5)

	count, mean, stddev := pp.TenantStats("nonexistent")
	if count != 0 || mean != 0 || stddev != 0 {
		t.Error("expected zeros for unknown tenant")
	}
}

func TestPromptProfile_10xSpike(t *testing.T) {
	pp := NewPromptProfile(5)

	// Train with ~50 char prompts
	for i := 0; i < 20; i++ {
		pp.Observe("team-a", "What is the weather in New York City today?")
	}

	// 10x spike (500+ chars)
	spike := strings.Repeat("Padding to make this very long. ", 30)
	result := pp.Observe("team-a", spike)

	if !result.IsAnomaly {
		t.Error("expected 10x spike detection")
	}
}

func TestCountWords(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"hello world", 2},
		{"  hello  world  ", 2},
		{"one", 1},
		{"", 0},
		{"hello\nworld\ttab", 3},
	}

	for _, tt := range tests {
		got := countWords(tt.input)
		if got != tt.expected {
			t.Errorf("countWords(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}
