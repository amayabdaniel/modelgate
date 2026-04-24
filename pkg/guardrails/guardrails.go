// Package guardrails integrates NVIDIA NeMo Guardrails
// (https://github.com/NVIDIA/NeMo-Guardrails) as a second-stage prompt
// checker in modelgate.
//
// NeMo Guardrails evaluates prompts against Colang-programmed dialogue
// flows — topic control, fact-checking, jailbreak detection, PII, etc.
// It is far richer than regex matching, so a deployment that cares about
// those dimensions runs NeMo alongside the existing PromptChecker rather
// than instead of it. This package wraps the REST surface NeMo exposes
// so the middleware can call Check(prompt) and get a verdict in the
// Violation shape the rest of modelgate already uses.
//
// The expected endpoint contract (served either by NeMo directly or by a
// thin adapter in front of it):
//
//	POST /v1/rails/check
//	Request:  {"prompt":"...","context":{"tenant":"..."}}
//	Response: {"allowed":true|false,"reasons":[{"rule":"jailbreak","message":"..."}]}
//
// Both shapes are small, stable, and map cleanly onto Colang's internal
// decision model.
package guardrails

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CheckRequest is the payload POSTed to the NeMo Guardrails check endpoint.
type CheckRequest struct {
	Prompt  string            `json:"prompt"`
	Context map[string]string `json:"context,omitempty"`
}

// CheckResponse is the payload the endpoint returns.
type CheckResponse struct {
	Allowed bool                `json:"allowed"`
	Reasons []CheckReason       `json:"reasons,omitempty"`
}

// CheckReason identifies one Colang rail that fired.
type CheckReason struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Violation is the modelgate-side representation of a guardrails finding.
// Kept in this package to avoid a circular import with pkg/security;
// the middleware translates between the two shapes.
type Violation struct {
	Rule     string
	Severity string
	Message  string
}

// Client is a thin HTTP client against the NeMo Guardrails check endpoint.
type Client struct {
	endpoint string
	http     *http.Client
}

// NewClient builds a client. endpoint is the base URL (without path —
// the check endpoint is appended as /v1/rails/check).
func NewClient(endpoint string) *Client {
	return &Client{
		endpoint: endpoint,
		http:     &http.Client{Timeout: 2 * time.Second},
	}
}

// Available reports whether a check endpoint is configured.
func (c *Client) Available() bool { return c != nil && c.endpoint != "" }

// ErrDisabled is returned by Check when the client has no endpoint set.
// Callers in middleware treat this as a skip, not a failure.
var ErrDisabled = errors.New("guardrails client disabled (no endpoint configured)")

// Check asks the NeMo Guardrails server whether the prompt should be
// allowed, returning any rails that fired. The returned violations map
// directly onto the Violation type used elsewhere in modelgate.
//
// Errors from the network or server fall through as-is; the caller
// decides whether a guardrails outage should fail-open or fail-closed.
// modelgate's default middleware fails open (no block) so the proxy
// does not become a hard dependency on NeMo being available.
func (c *Client) Check(ctx context.Context, prompt string, tenantContext map[string]string) ([]Violation, error) {
	if !c.Available() {
		return nil, ErrDisabled
	}

	body, err := json.Marshal(CheckRequest{Prompt: prompt, Context: tenantContext})
	if err != nil {
		return nil, fmt.Errorf("marshal guardrails request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/v1/rails/check", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("guardrails request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("guardrails server returned %d: %s", resp.StatusCode, string(snippet))
	}

	var out CheckResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode guardrails response: %w", err)
	}
	if out.Allowed {
		return nil, nil
	}

	vs := make([]Violation, 0, len(out.Reasons))
	for _, r := range out.Reasons {
		vs = append(vs, Violation{
			Rule:     "guardrails:" + r.Rule,
			Severity: fallback(r.Severity, "warning"),
			Message:  fallback(r.Message, "blocked by NeMo Guardrails rail: "+r.Rule),
		})
	}
	// If the server refused without listing reasons, emit a synthetic
	// violation so downstream audit logging still records a rule name.
	if len(vs) == 0 {
		vs = append(vs, Violation{
			Rule:     "guardrails:unspecified",
			Severity: "warning",
			Message:  "request blocked by NeMo Guardrails (no reason provided)",
		})
	}
	return vs, nil
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
