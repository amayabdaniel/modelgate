package v1alpha1

import "testing"

func TestInferencePolicySpec_ValidFull(t *testing.T) {
	spec := &InferencePolicySpec{
		Budgets: []TenantBudget{
			{Tenant: "support-team", MonthlyLimitUSD: 3000, AlertAtPercent: 80},
			{Tenant: "dev-team", MonthlyLimitUSD: 500, AlertAtPercent: 90},
		},
		Security: SecurityPolicy{
			PromptInjectionProtection: true,
			PIIRedaction:              true,
			BlockedPatterns:           []string{"ignore previous instructions"},
			MaxPromptTokens:           8192,
		},
		Routing: RoutingPolicy{
			Rules: []RoutingRule{
				{Condition: "prompt_tokens < 2000", Model: "qwen3-8b"},
				{Condition: "prompt_tokens >= 2000", Model: "llama3-70b"},
			},
		},
		RateLimits: []RateLimit{
			{Tenant: "support-team", TokensPerMinute: 50000, RequestsPerMinute: 100},
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

func TestTenantBudget_MissingTenant(t *testing.T) {
	b := &TenantBudget{MonthlyLimitUSD: 1000}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for missing tenant")
	}
}

func TestTenantBudget_ZeroBudget(t *testing.T) {
	b := &TenantBudget{Tenant: "test", MonthlyLimitUSD: 0}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for zero budget")
	}
}

func TestTenantBudget_NegativeBudget(t *testing.T) {
	b := &TenantBudget{Tenant: "test", MonthlyLimitUSD: -100}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for negative budget")
	}
}

func TestTenantBudget_InvalidAlertPercent(t *testing.T) {
	b := &TenantBudget{Tenant: "test", MonthlyLimitUSD: 1000, AlertAtPercent: 150}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for alert_at_percent > 100")
	}
}

func TestRateLimit_ZeroTokens(t *testing.T) {
	r := &RateLimit{TokensPerMinute: 0}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for zero tokens_per_minute")
	}
}

func TestRateLimit_Valid(t *testing.T) {
	r := &RateLimit{Tenant: "team-a", TokensPerMinute: 50000, RequestsPerMinute: 200}
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

func TestRoutingRules_Structure(t *testing.T) {
	rules := []RoutingRule{
		{Condition: "prompt_tokens < 2000", Model: "small-model"},
		{Condition: "prompt_tokens >= 2000", Model: "large-model"},
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Model != "small-model" {
		t.Errorf("expected small-model, got %s", rules[0].Model)
	}
}
