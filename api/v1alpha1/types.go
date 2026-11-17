package v1alpha1

import "fmt"

// InferencePolicySpec defines governance rules for AI inference traffic.
//
// Prior versions carried a Routing RoutingPolicy field with Rules of
// {if, model} shape, and a Budgets []TenantBudget field with
// MonthlyLimitUSD plus AlertAtPercent, both documented in
// examples/policy.yaml and advertised in the README as if enforced —
// but no code in the tree ever consumed them. An operator who wrote
// either block into their policy saw a silently-ignored config. Each
// was removed rather than kept as scaffolding (the SECURITY.md Cost
// abuse row previously marked Budgets "Implemented (types), TODO
// (enforcement)" — the "(types)" part was the scaffolding this
// deletion retires) so the schema stops promising controls the
// runtime doesn't enforce. The honest re-introduction for each is to
// add it back the same commit that wires the matching enforcer
// (router, cost tracker + alert emitter + billing persistence).
type InferencePolicySpec struct {
	// Security defines prompt-level security controls.
	Security SecurityPolicy `yaml:"security,omitempty" json:"security,omitempty"`

	// RateLimits defines token-aware rate limiting.
	RateLimits []RateLimit `yaml:"rateLimits,omitempty" json:"rateLimits,omitempty"`
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

func (r *RateLimit) Validate() error {
	if r.TokensPerMinute <= 0 {
		return fmt.Errorf("tokens_per_minute must be positive")
	}
	return nil
}
