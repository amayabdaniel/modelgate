package v1alpha1

import "fmt"

// InferencePolicySpec defines governance rules for AI inference traffic.
type InferencePolicySpec struct {
	// Budgets defines per-tenant spending limits.
	Budgets []TenantBudget `yaml:"budgets,omitempty" json:"budgets,omitempty"`

	// Security defines prompt-level security controls.
	Security SecurityPolicy `yaml:"security,omitempty" json:"security,omitempty"`

	// Routing defines model routing rules based on request properties.
	Routing RoutingPolicy `yaml:"routing,omitempty" json:"routing,omitempty"`

	// RateLimits defines token-aware rate limiting.
	RateLimits []RateLimit `yaml:"rateLimits,omitempty" json:"rateLimits,omitempty"`
}

type TenantBudget struct {
	Tenant         string  `yaml:"tenant" json:"tenant"`
	MonthlyLimitUSD float64 `yaml:"monthly_limit_usd" json:"monthly_limit_usd"`
	AlertAtPercent  int     `yaml:"alert_at_percent,omitempty" json:"alert_at_percent,omitempty"`
}

type SecurityPolicy struct {
	PromptInjectionProtection bool     `yaml:"prompt_injection_protection,omitempty" json:"prompt_injection_protection,omitempty"`
	PIIRedaction              bool     `yaml:"pii_redaction,omitempty" json:"pii_redaction,omitempty"`
	BlockedPatterns           []string `yaml:"blocked_patterns,omitempty" json:"blocked_patterns,omitempty"`
	MaxPromptTokens           int      `yaml:"max_prompt_tokens,omitempty" json:"max_prompt_tokens,omitempty"`
}

type RoutingPolicy struct {
	Rules []RoutingRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

type RoutingRule struct {
	Condition string `yaml:"if" json:"if"`
	Model     string `yaml:"model" json:"model"`
}

type RateLimit struct {
	Tenant         string `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	TokensPerMinute int    `yaml:"tokens_per_minute" json:"tokens_per_minute"`
	RequestsPerMinute int  `yaml:"requests_per_minute,omitempty" json:"requests_per_minute,omitempty"`
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
