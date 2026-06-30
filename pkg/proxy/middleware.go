package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/pkg/guardrails"
	"github.com/amayabdaniel/modelgate/pkg/security"
)

// promptHash returns a 64-bit hex prefix of SHA-256(prompt). We
// truncate to 16 hex chars so the on-wire payload stays compact;
// collision risk in any realistic per-tenant DFP window (~thousands of
// requests) is negligible.
func promptHash(prompt string) string {
	if prompt == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(sum[:8])
}

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
//
// PromptLength, PromptHash, and ProcessingLatencyMs enable per-request
// DFP detection on the consumer side without leaking prompt content
// across the network: a hash collision is the only way to identify a
// "same prompt fired twice" pattern, and the prompt itself never
// leaves this process.
//
// PromptHash is the first 16 hex chars of SHA-256(prompt) — 64 bits is
// enough to make accidental collisions vanishingly rare in a
// detection-window-sized event set while keeping payloads compact.
type AuditEvent struct {
	Model               string               `json:"model"`
	Tenant              string               `json:"tenant"`
	Action              string               `json:"action"` // "allowed", "blocked"
	Reason              string               `json:"reason,omitempty"`
	Violations          []security.Violation `json:"violations,omitempty"`
	PromptLength        int                  `json:"prompt_length,omitempty"`
	PromptHash          string               `json:"prompt_hash,omitempty"`
	ProcessingLatencyMs int64                `json:"processing_latency_ms,omitempty"`
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
	// Capture request entry time so every audit event carries the
	// middleware's processing latency. The DFP consumer uses this as
	// a signal — expensive paths (guardrails) take longer, so a sudden
	// drop in latency may mean checks are being bypassed.
	requestStart := time.Now()

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

	// emit wraps every auditFn call so the per-request DFP fields land
	// on every event regardless of which branch reaches the emit site.
	// Pre-computed hash + length avoid re-hashing the prompt N times
	// across the blocked/allowed branches.
	promptLen := len(prompt)
	promptH := promptHash(prompt)
	emit := func(ev AuditEvent) {
		if m.auditFn == nil {
			return
		}
		if ev.PromptLength == 0 {
			ev.PromptLength = promptLen
		}
		if ev.PromptHash == "" {
			ev.PromptHash = promptH
		}
		if ev.ProcessingLatencyMs == 0 {
			ev.ProcessingLatencyMs = time.Since(requestStart).Milliseconds()
		}
		m.auditFn(ev)
	}

	// Acquire read lock for thread-safe checker access (supports hot-reload)
	m.mu.RLock()
	checker := m.checker
	policy := m.policy
	m.mu.RUnlock()

	// Check rate limits (token-aware, per tenant)
	if m.rateLimiter != nil && tenant != "" {
		estimatedTokens := len(prompt) / 4 // rough estimate: 1 token ≈ 4 chars
		if !m.rateLimiter.Allow(tenant, estimatedTokens) {
			emit(AuditEvent{
				Model:  req.Model,
				Tenant: tenant,
				Action: "blocked",
				Reason: "Rate limit exceeded",
			})

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
		emit(AuditEvent{
			Model:      req.Model,
			Tenant:     tenant,
			Action:     "blocked",
			Reason:     violations[0].Message,
			Violations: violations,
		})

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
				emit(AuditEvent{
					Model:  req.Model,
					Tenant: tenant,
					Action: "blocked",
					Reason: "Guardrails unreachable (fail-closed)",
				})
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
			emit(AuditEvent{
				Model:      req.Model,
				Tenant:     tenant,
				Action:     "blocked",
				Reason:     securityVs[0].Message,
				Violations: securityVs,
			})
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
		emit(AuditEvent{
			Model:  req.Model,
			Tenant: tenant,
			Action: "blocked",
			Reason: "PII detected in prompt",
		})

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
	emit(AuditEvent{
		Model:  req.Model,
		Tenant: tenant,
		Action: "allowed",
	})

	m.next.ServeHTTP(w, r)
}
