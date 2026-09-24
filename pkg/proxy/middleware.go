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
//
// DRIFT NOTE — Action values are documented in three places without a
// test wiring them together: this godoc block, SECURITY.md principle #4
// ("Audit everything"), and README.md's "Audit contract" paragraph. If
// you add a fourth Action value or rename one, update all three; a
// prior incarnation of SECURITY.md principle #5 became silently false
// when the guardrails fail-open default landed without anyone
// revisiting the doc. Downstream: gpudab-server's AuditConsumer at
// internal/source/cuanomaly/audit_consumer.go switches on "allowed"
// and "blocked" and passes any other Action through as Requests-only,
// so a new value is safe to add there without a code change but the
// docstring's Action-mapping table needs updating too.
//
// Action values:
//   - "allowed"     — all configured checks ran and none fired. Reason
//     may still be set to note a non-terminal event
//     (e.g. guardrails unavailable under fail-open
//     policy — the request was forwarded, but the audit
//     trail records that guardrails did NOT run).
//   - "blocked"     — a check fired and the request never reached the
//     upstream; Violations describes what fired.
//   - "passthrough" — the middleware could not inspect this request
//     (non-POST verb, unparseable body, non-chat schema)
//     but it DID reach the upstream. Emitted so the
//     audit trail never silently omits a request that
//     hit the LLM — a compliance claim of the form "we
//     can prove what went through" depends on the floor
//     that every request either was audited here or was
//     rejected here. Downstream consumers of the audit
//     stream (gpudab AuditConsumer) count these as
//     Requests but neither Allowed nor Blocked.
type AuditEvent struct {
	Model               string               `json:"model"`
	Tenant              string               `json:"tenant"`
	Action              string               `json:"action"` // one of AuditActions
	Reason              string               `json:"reason,omitempty"`
	Violations          []security.Violation `json:"violations,omitempty"`
	PromptLength        int                  `json:"prompt_length,omitempty"`
	PromptHash          string               `json:"prompt_hash,omitempty"`
	ProcessingLatencyMs int64                `json:"processing_latency_ms,omitempty"`
}

// AuditActions is the canonical list of values the AuditEvent.Action
// field is allowed to take. It is the single source of truth cross-
// referenced by the AuditEvent godoc's DRIFT NOTE, SECURITY.md
// principle #4, and README.md's Audit contract paragraph — each of
// those docs carries a machine-readable marker
//
//	<!-- audit-action-values: allowed blocked passthrough -->
//
// that TestAuditActionsSyncedWithDocs validates against this slice in
// both directions: any value here must be documented as `"X"` in each
// doc, and any value the marker declares must appear in this slice.
// The values themselves stay as string literals at their emit sites
// because gpudab-server's AuditConsumer switches on the same literals
// across a repo boundary — a shared symbol would help drift here but
// would not help drift across the wire.
var AuditActions = []string{
	"allowed",
	"blocked",
	"passthrough",
}

// OpenAIChatRequest is a minimal representation of an OpenAI chat completion request.
type OpenAIChatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// buildFromPolicy is the single place that turns an InferencePolicySpec
// into the three policy-derived pieces of middleware state — the
// prompt checker, the token-bucket rate limiter, and the guardrails
// client. Both NewMiddleware (startup) and PolicyReloader (hot-reload)
// route through it so a reload applies the WHOLE policy, not just the
// checker. Prior to being extracted, reload only rebuilt the checker
// and silently dropped changes to rateLimits and guardrails_endpoint —
// an operator raising a rate limit or pointing at a new NeMo endpoint
// via policy hot-reload got no effect and no warning. Kept as a pure
// function so it can be tested and reasoned about without middleware
// state to set up.
func buildFromPolicy(policy v1alpha1.InferencePolicySpec) (*security.PromptChecker, *security.TokenBucket, *guardrails.Client, error) {
	checker, err := security.NewPromptChecker(policy.Security)
	if err != nil {
		return nil, nil, nil, err
	}

	// Rate limiter is nil when the policy has no rate limits, so
	// ServeHTTP's `if rateLimiter != nil` branch stays intact when
	// hot-reload removes every RateLimits entry. Burst is fixed at 2x
	// rate — matches the value NewMiddleware used before extraction so
	// existing tests keep their exact numeric behaviour.
	var rateLimiter *security.TokenBucket
	if len(policy.RateLimits) > 0 {
		rateLimiter = security.NewTokenBucket(
			policy.RateLimits[0].TokensPerMinute,
			policy.RateLimits[0].TokensPerMinute*2,
		)
	}

	// Optional NeMo Guardrails client — activates when the policy names
	// an endpoint. Nil when the endpoint is empty, so removing the
	// endpoint via reload actually disables guardrails, and adding one
	// enables it. ServeHTTP checks Available() before use.
	var gr *guardrails.Client
	if policy.Security.GuardrailsEndpoint != "" {
		gr = guardrails.NewClient(policy.Security.GuardrailsEndpoint)
	}

	return checker, rateLimiter, gr, nil
}

// Overflows returns the running count of Allow calls that fell into
// the shared OverflowTenant bucket because the rate limiter's
// distinct-tenant cap was reached. Reads under RLock so a concurrent
// reload's rate-limiter swap doesn't race. Zero when no limiter is
// configured. Satisfies proxy.rateLimiterProbe for stats wiring.
//
// The count resets on policy reload — the new TokenBucket starts at
// zero. That's a deliberate trade: making the count survive reload
// would require aggregating into a Stats-side counter, which either
// duplicates the value across two locations or forces every Allow
// call to double-write. For an operational signal watched via /stats
// polling, the short-lived reset around infrequent reloads is
// acceptable; the value the /stats snapshot renders is honest for
// the currently-active policy, which is the meaningful window.
func (m *Middleware) Overflows() int64 {
	m.mu.RLock()
	rl := m.rateLimiter
	m.mu.RUnlock()
	if rl == nil {
		return 0
	}
	return rl.Overflows()
}

// NewMiddleware creates a security middleware from a policy spec.
func NewMiddleware(policy v1alpha1.InferencePolicySpec, next http.Handler, auditFn func(AuditEvent)) (*Middleware, error) {
	checker, rateLimiter, gr, err := buildFromPolicy(policy)
	if err != nil {
		return nil, err
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

	// auditRaw is the audit contract's floor for pre-parse code paths
	// that don't yet know the prompt (non-POST, body-read failure,
	// unparseable body). Every request that reaches this middleware
	// emits at least one audit event — silent forwarding is what would
	// break the "prove what went through the LLM" compliance claim.
	auditRaw := func(ev AuditEvent) {
		if m.auditFn == nil {
			return
		}
		if ev.ProcessingLatencyMs == 0 {
			ev.ProcessingLatencyMs = time.Since(requestStart).Milliseconds()
		}
		m.auditFn(ev)
	}

	// Non-POST verbs (GET /v1/models, HEAD, OPTIONS, DELETE /v1/files/*)
	// pass through to the upstream, so the audit trail MUST record
	// them — otherwise a GET that returns uploaded file content leaves
	// no trace here. Audited as "passthrough" (distinct from "allowed")
	// so downstream consumers can filter on inspected-vs-not.
	if r.Method != http.MethodPost {
		auditRaw(AuditEvent{
			Tenant: r.Header.Get("X-Tenant"),
			Action: "passthrough",
			Reason: "non-inspectable method: " + r.Method,
		})
		m.next.ServeHTTP(w, r)
		return
	}

	// Enforce max request body size (10MB)
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		// The request never reaches upstream on this path, but the
		// attempt still belongs in the audit trail — a client repeatedly
		// hitting MaxBytesReader is a DFP signal and needs to be visible
		// on /v1/audit/stream.
		auditRaw(AuditEvent{
			Tenant: r.Header.Get("X-Tenant"),
			Action: "blocked",
			Reason: "body read error",
		})
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var req OpenAIChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		// The body didn't fit the OpenAI chat schema. Two shapes fall
		// here: a non-chat endpoint on the same proxy (embeddings,
		// moderations, files) and — the one that reaches an LLM with
		// user content — a chat request using OpenAI's multimodal
		// Content-as-array shape our string-typed field can't decode.
		// Either way the middleware never inspected it, so the audit
		// trail records "passthrough" with the reason instead of
		// silently going quiet.
		auditRaw(AuditEvent{
			Tenant: r.Header.Get("X-Tenant"),
			Action: "passthrough",
			Reason: "body does not match chat schema",
		})
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

	// Capture every policy-derived field under one RLock so a hot-reload
	// firing partway through this handler can't split the request across
	// two policies (e.g. old checker + new rateLimiter). Reload writes
	// all four fields together under m.mu.Lock(); we read all four
	// together under RLock and then use only the locals. rateLimiter and
	// guardrails used to be read lock-free below on the assumption that
	// they were set once at startup — no longer true now that reload
	// rebuilds them.
	m.mu.RLock()
	checker := m.checker
	policy := m.policy
	rateLimiter := m.rateLimiter
	gr := m.guardrails
	m.mu.RUnlock()

	// Check rate limits (token-aware, per tenant)
	if rateLimiter != nil && tenant != "" {
		estimatedTokens := len(prompt) / 4 // rough estimate: 1 token ≈ 4 chars
		if !rateLimiter.Allow(tenant, estimatedTokens) {
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
	//
	// guardrailsFailedOpen tracks whether the fail-open branch fired.
	// When it does, the request is forwarded — but the final "allowed"
	// audit event needs to say so, or the audit trail claims a check
	// ran that never did. Without this signal, an operator asking "did
	// guardrails inspect this prompt?" sees the same "allowed" record
	// for the outage window as for a clean pass.
	//
	// gr was captured under the top-of-handler RLock along with the
	// other policy-derived fields; no second RLock needed here.
	var guardrailsFailedOpen bool
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
			guardrailsFailedOpen = true
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

	// All checks passed — audit and forward. When guardrails errored
	// under fail-open policy the request WAS forwarded but guardrails
	// did NOT actually inspect the prompt; the audit event records
	// that in its Reason so downstream can distinguish a clean pass
	// from a pass-during-outage.
	allowedReason := ""
	if guardrailsFailedOpen {
		allowedReason = "guardrails unavailable (allowed by fail-open policy)"
	}
	emit(AuditEvent{
		Model:  req.Model,
		Tenant: tenant,
		Action: "allowed",
		Reason: allowedReason,
	})

	m.next.ServeHTTP(w, r)
}
