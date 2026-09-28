package v1alpha1

import "fmt"

// InferencePolicySpec defines governance rules for AI inference traffic.
//
// A prior version carried a Routing RoutingPolicy field with Rules of
// {if, model} shape, documented in examples/policy.yaml and tested in
// TestRoutingRules_Structure — but no code in the tree ever consumed
// it. An operator who wrote a routing block into their policy saw a
// silently-ignored config. Removed rather than kept as scaffolding so
// the schema stops lying about capabilities the runtime doesn't
// enforce; the honest re-introduction is to add the field back the
// same commit that wires the router.
type InferencePolicySpec struct {
	// Budgets defines per-tenant spending limits.
	Budgets []TenantBudget `yaml:"budgets,omitempty" json:"budgets,omitempty"`

	// Security defines prompt-level security controls.
	Security SecurityPolicy `yaml:"security,omitempty" json:"security,omitempty"`

	// RateLimits defines token-aware rate limiting.
	RateLimits []RateLimit `yaml:"rateLimits,omitempty" json:"rateLimits,omitempty"`
}

type TenantBudget struct {
	Tenant          string  `yaml:"tenant" json:"tenant"`
	MonthlyLimitUSD float64 `yaml:"monthly_limit_usd" json:"monthly_limit_usd"`
	AlertAtPercent  int     `yaml:"alert_at_percent,omitempty" json:"alert_at_percent,omitempty"`
}

type SecurityPolicy struct {
	PromptInjectionProtection bool     `yaml:"prompt_injection_protection,omitempty" json:"prompt_injection_protection,omitempty"`
	PIIRedaction              bool     `yaml:"pii_redaction,omitempty" json:"pii_redaction,omitempty"`
	BlockedPatterns           []string `yaml:"blocked_patterns,omitempty" json:"blocked_patterns,omitempty"`
	MaxPromptTokens           int      `yaml:"max_prompt_tokens,omitempty" json:"max_prompt_tokens,omitempty"`

	// GuardrailsEndpoint, when set, points modelgate at a NeMo Guardrails
	// server. Every prompt that passes regex checks is re-evaluated by
	// Colang rails before being forwarded to the upstream LLM. Unset to
	// disable; regex-based checks continue to run.
	GuardrailsEndpoint string `yaml:"guardrails_endpoint,omitempty" json:"guardrails_endpoint,omitempty"`

	// GuardrailsFailClosed, when true, blocks a request if the Guardrails
	// endpoint is unreachable or errors. Defaults to false (fail-open) so
	// NeMo outages do not take down the proxy.
	GuardrailsFailClosed bool `yaml:"guardrails_fail_closed,omitempty" json:"guardrails_fail_closed,omitempty"`
}

// RateLimit configures the per-tenant token bucket enforced by
// pkg/security/TokenBucket. Prior versions also carried a
// RequestsPerMinute int, documented in examples/policy.yaml and
// README.md — but the TokenBucket only reads TokensPerMinute, so a
// value in RequestsPerMinute was silently ignored. Removed with the
// docs so the schema stops promising a control the code doesn't
// enforce; the honest re-introduction is to add the field back the
// same commit that wires the requests-per-minute limiter.
type RateLimit struct {
	Tenant          string `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	TokensPerMinute int    `yaml:"tokens_per_minute" json:"tokens_per_minute"`
}

// Validate checks the policy spec for correctness.
func (s *InferencePolicySpec) Validate() error {
	for _, b := range s.Budgets {
		if err := b.Validate(); err != nil {
			return err
		}
	}
	for _, r := range s.RateLimits {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	if s.Security.MaxPromptTokens < 0 {
		return fmt.Errorf("max_prompt_tokens must be non-negative")
	}
	return nil
}

func (b *TenantBudget) Validate() error {
	if b.Tenant == "" {
		return fmt.Errorf("tenant name is required in budget")
	}
	if b.MonthlyLimitUSD <= 0 {
		return fmt.Errorf("monthly_limit_usd must be positive for tenant %q", b.Tenant)
	}
	if b.AlertAtPercent < 0 || b.AlertAtPercent > 100 {
		return fmt.Errorf("alert_at_percent must be 0-100 for tenant %q", b.Tenant)
	}
	return nil
}

func (r *RateLimit) Validate() error {
	if r.TokensPerMinute <= 0 {
		return fmt.Errorf("tokens_per_minute must be positive")
	}
	return nil
}
