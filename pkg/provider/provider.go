// Package provider abstracts the upstream LLM backend modelgate proxies to.
//
// Different providers (generic OpenAI-compatible, NVIDIA NIM, vLLM, etc.)
// share the same OpenAI-style request/response shape but differ in:
//   - Authentication header conventions
//   - Health probe paths
//   - Model path routing
//
// This package isolates those differences so the proxy middleware stays
// provider-agnostic.
package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Provider describes an upstream LLM backend.
type Provider interface {
	// Name is a short identifier used in logs, stats, and the --provider flag.
	Name() string

	// Target returns the upstream base URL the reverse proxy forwards to.
	Target() *url.URL

	// PrepareRequest mutates an outbound request before it is forwarded —
	// typically to inject auth headers or rewrite paths.
	PrepareRequest(r *http.Request)

	// HealthCheck performs a readiness probe against the upstream.
	// Returns nil if reachable and ready to serve requests.
	HealthCheck(ctx context.Context, client *http.Client) error
}

// FromName resolves a provider by its --provider flag value. Unknown names
// yield an error so misconfiguration fails fast at startup.
func FromName(name, backendURL string) (Provider, error) {
	target, err := url.Parse(backendURL)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("backend URL must include scheme and host: %q", backendURL)
	}

	switch name {
	case "", "generic", "openai", "ollama", "vllm":
		return &Generic{name: fallback(name, "generic"), target: target}, nil
	case "nim":
		return NewNIM(target), nil
	default:
		return nil, fmt.Errorf("unknown provider %q (want: generic, nim, openai, ollama, vllm)", name)
	}
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
