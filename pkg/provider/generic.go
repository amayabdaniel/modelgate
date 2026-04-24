package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Generic is the legacy passthrough provider. It preserves historical
// behavior for OpenAI-compatible backends (OpenAI, Ollama, vLLM, etc.):
// no header injection, health probe against "/" at the target.
type Generic struct {
	name   string
	target *url.URL
}

func (g *Generic) Name() string       { return g.name }
func (g *Generic) Target() *url.URL   { return g.target }
func (g *Generic) PrepareRequest(*http.Request) {}

func (g *Generic) HealthCheck(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.target.String()+"/", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("generic health probe: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("generic health probe: upstream returned %d", resp.StatusCode)
	}
	return nil
}
