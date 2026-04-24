package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/pkg/guardrails"
	"github.com/amayabdaniel/modelgate/pkg/security"
)

// Middleware intercepts OpenAI-compatible LLM API requests and applies
// security checks, rate limiting, and audit logging before forwarding.
type Middleware struct {
	mu          sync.RWMutex
	checker     *security.PromptChecker
	policy      v1alpha1.InferencePolicySpec
	next        http.Handler
	auditFn     func(AuditEvent)
	rateLimiter *security.TokenBucket
	guardrails  *guardrails.Client
}

// AuditEvent records a request passing through the middleware.
type AuditEvent struct {
	Model      string            `json:"model"`
	Tenant     string            `json:"tenant"`
	Action     string            `json:"action"` // "allowed", "blocked"
	Reason     string            `json:"reason,omitempty"`
	Violations []security.Violation `json:"violations,omitempty"`
}

// OpenAIChatRequest is a minimal representation of an OpenAI chat completion request.
type OpenAIChatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// NewMiddleware creates a security middleware from a policy spec.
func NewMiddleware(policy v1alpha1.InferencePolicySpec, next http.Handler, auditFn func(AuditEvent)) (*Middleware, error) {
	checker, err := security.NewPromptChecker(policy.Security)
	if err != nil {
		return nil, err
	}

	// Build rate limiter from policy if rate limits are defined
	var rateLimiter *security.TokenBucket
	if len(policy.RateLimits) > 0 {
		// Use the first rate limit's tokens_per_minute as default capacity
		rateLimiter = security.NewTokenBucket(
			policy.RateLimits[0].TokensPerMinute,
			policy.RateLimits[0].TokensPerMinute*2, // burst = 2x rate
		)
	}

	// Optional NeMo Guardrails client — activates when the policy names
	// an endpoint. Nil otherwise; ServeHTTP checks Available() before use.
	var gr *guardrails.Client
	if policy.Security.GuardrailsEndpoint != "" {
		gr = guardrails.NewClient(policy.Security.GuardrailsEndpoint)
	}

	return &Middleware{
		checker:     checker,
		policy:      policy,
		next:        next,
		auditFn:     auditFn,
		rateLimiter: rateLimiter,
		guardrails:  gr,
	}, nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers on all responses
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))

	// Only check POST requests to chat/completions endpoints
	if r.Method != http.MethodPost {
		m.next.ServeHTTP(w, r)
		return
	}

	// Enforce max request body size (10MB)
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req OpenAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// Not a valid chat request — pass through
		m.next.ServeHTTP(w, r)
		return
	}

	// Extract all user message content for checking
	var prompt string
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			prompt += msg.Content + "\n"
		}
	}

	tenant := r.Header.Get("X-Tenant")

	// Acquire read lock for thread-safe checker access (supports hot-reload)
	m.mu.RLock()
	checker := m.checker
	policy := m.policy
	m.mu.RUnlock()

	// Check rate limits (token-aware, per tenant)
	if m.rateLimiter != nil && tenant != "" {
		estimatedTokens := len(prompt) / 4 // rough estimate: 1 token ≈ 4 chars
		if !m.rateLimiter.Allow(tenant, estimatedTokens) {
			if m.auditFn != nil {
				m.auditFn(AuditEvent{
					Model:  req.Model,
					Tenant: tenant,
					Action: "blocked",
					Reason: "Rate limit exceeded",
				})
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "Token rate limit exceeded for tenant",
					"type":    "rate_limited",
					"code":    "tokens_per_minute",
				},
			})
			return
		}
	}

	// Check prompt security
	violations := checker.Check(prompt)
	if len(violations) > 0 {
		if m.auditFn != nil {
			m.auditFn(AuditEvent{
				Model:      req.Model,
				Tenant:     tenant,
				Action:     "blocked",
				Reason:     violations[0].Message,
				Violations: violations,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Request blocked by inference security policy",
				"type":    "policy_violation",
				"code":    violations[0].Rule,
			},
		})
		return
	}

	// NeMo Guardrails check — runs after regex checks when configured.
	// Colang rails produce a richer violation taxonomy (jailbreak,
	// off-topic, hallucination, etc.). Failures default to fail-open so
	// NeMo outages do not take down the proxy; policy can opt into
	// fail-closed with GuardrailsFailClosed.
	m.mu.RLock()
	gr := m.guardrails
	m.mu.RUnlock()
	if gr != nil && gr.Available() {
		ctx := r.Context()
		grViolations, grErr := gr.Check(ctx, prompt, map[string]string{"tenant": tenant, "model": req.Model})
		switch {
		case grErr != nil && !errors.Is(grErr, guardrails.ErrDisabled):
			if policy.Security.GuardrailsFailClosed {
				if m.auditFn != nil {
					m.auditFn(AuditEvent{
						Model:  req.Model,
						Tenant: tenant,
						Action: "blocked",
						Reason: "Guardrails unreachable (fail-closed)",
					})
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"message": "Policy engine unavailable",
						"type":    "guardrails_unavailable",
						"code":    "guardrails",
					},
				})
				return
			}
			log.Printf("modelgate: guardrails check failed (fail-open): %v", grErr)

		case len(grViolations) > 0:
			securityVs := make([]security.Violation, 0, len(grViolations))
			for _, v := range grViolations {
				securityVs = append(securityVs, security.Violation{
					Rule:     v.Rule,
					Severity: v.Severity,
					Message:  v.Message,
				})
			}
			if m.auditFn != nil {
				m.auditFn(AuditEvent{
					Model:      req.Model,
					Tenant:     tenant,
					Action:     "blocked",
					Reason:     securityVs[0].Message,
					Violations: securityVs,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "Request blocked by NeMo Guardrails policy",
					"type":    "policy_violation",
					"code":    securityVs[0].Rule,
				},
			})
			return
		}
	}

	// Check PII in prompt if redaction is enabled
	if policy.Security.PIIRedaction && security.ContainsPII(prompt) {
		if m.auditFn != nil {
			m.auditFn(AuditEvent{
				Model:  req.Model,
				Tenant: tenant,
				Action: "blocked",
				Reason: "PII detected in prompt",
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{
				"message": "Request contains personally identifiable information",
				"type":    "pii_detected",
				"code":    "pii_redaction",
			},
		})
		return
	}

	// All checks passed — audit and forward
	if m.auditFn != nil {
		m.auditFn(AuditEvent{
			Model:  req.Model,
			Tenant: tenant,
			Action: "allowed",
		})
	}

	m.next.ServeHTTP(w, r)
}
