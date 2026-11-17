package v1alpha1

import "testing"

func TestInferencePolicySpec_ValidFull(t *testing.T) {
	spec := &InferencePolicySpec{
		Security: SecurityPolicy{
			PromptInjectionProtection: true,
			PIIRedaction:              true,
			BlockedPatterns:           []string{"ignore previous instructions"},
			MaxPromptTokens:           8192,
		},
		RateLimits: []RateLimit{
			{Tenant: "support-team", TokensPerMinute: 50000},
		},
	}

	if err := spec.Validate(); err != nil {
		t.Fatalf("expected valid spec, got error: %v", err)
	}
}

func TestInferencePolicySpec_MinimalValid(t *testing.T) {
	spec := &InferencePolicySpec{}
	if err := spec.Validate(); err != nil {
		t.Fatalf("empty spec should be valid, got: %v", err)
	}
}

func TestRateLimit_ZeroTokens(t *testing.T) {
	r := &RateLimit{TokensPerMinute: 0}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for zero tokens_per_minute")
	}
}

func TestRateLimit_Valid(t *testing.T) {
	r := &RateLimit{Tenant: "team-a", TokensPerMinute: 50000}
	if err := r.Validate(); err != nil {
		t.Fatalf("expected valid rate limit, got: %v", err)
	}
}

func TestSecurityPolicy_NegativeMaxTokens(t *testing.T) {
	spec := &InferencePolicySpec{
		Security: SecurityPolicy{MaxPromptTokens: -1},
	}
	if err := spec.Validate(); err == nil {
		t.Fatal("expected error for negative max_prompt_tokens")
	}
}

