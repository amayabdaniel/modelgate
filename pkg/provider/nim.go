package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
)

// NIM is NVIDIA Inference Microservice — NGC-hosted, OpenAI-compatible.
//
// Differences vs. Generic:
//   - Requires `Authorization: Bearer <NIM_API_KEY>` on every request.
//     (NIM also accepts the Ngc-Api-Key header; we standardize on Bearer.)
//   - Health probe at /v1/health/ready rather than /.
//   - Optionally forwards an NGC organization header when configured.
//
// API key is read from NIM_API_KEY at middleware-call time so keys can be
// rotated without a restart (the proxy re-reads on each request). Missing
// keys are not fatal — the upstream will return 401 and modelgate will
// surface that to the caller unchanged.
type NIM struct {
	target  *url.URL
	envAuth string // name of the env var holding the Bearer token
	envOrg  string // optional NGC org header source
}

// NewNIM constructs a NIM provider pointing at target. Defaults env sources
// to NIM_API_KEY and NGC_ORG_ID.
func NewNIM(target *url.URL) *NIM {
	return &NIM{target: target, envAuth: "NIM_API_KEY", envOrg: "NGC_ORG_ID"}
}

func (n *NIM) Name() string     { return "nim" }
func (n *NIM) Target() *url.URL { return n.target }

func (n *NIM) PrepareRequest(r *http.Request) {
	if key := os.Getenv(n.envAuth); key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	if org := os.Getenv(n.envOrg); org != "" {
		r.Header.Set("NGC-Organization", org)
	}
	// Identify traffic to the upstream for NVIDIA's own telemetry.
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", "modelgate/nim")
	}
}

func (n *NIM) HealthCheck(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, n.target.String()+"/v1/health/ready", nil)
	if err != nil {
		return err
	}
	n.PrepareRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("nim health probe: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("nim not ready: upstream returned %d", resp.StatusCode)
	}
	return nil
}
