package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFromName_Known(t *testing.T) {
	cases := map[string]string{
		"":        "generic",
		"generic": "generic",
		"openai":  "openai",
		"ollama":  "ollama",
		"vllm":    "vllm",
		"nim":     "nim",
	}
	for in, want := range cases {
		p, err := FromName(in, "http://example.com")
		if err != nil {
			t.Errorf("FromName(%q): unexpected error: %v", in, err)
			continue
		}
		if p.Name() != want {
			t.Errorf("FromName(%q).Name() = %q, want %q", in, p.Name(), want)
		}
	}
}

func TestFromName_UnknownProvider(t *testing.T) {
	if _, err := FromName("anthropic", "http://example.com"); err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestFromName_InvalidURL(t *testing.T) {
	if _, err := FromName("generic", "not-a-url"); err == nil {
		t.Error("expected error for missing scheme/host")
	}
	if _, err := FromName("generic", "http://"); err == nil {
		t.Error("expected error for URL with no host")
	}
}

func TestGeneric_NoHeaderMutation(t *testing.T) {
	p, _ := FromName("generic", "http://example.com")
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer original")
	p.PrepareRequest(req)

	if got := req.Header.Get("Authorization"); got != "Bearer original" {
		t.Errorf("generic must not overwrite Authorization, got %q", got)
	}
}

func TestNIM_InjectsBearerFromEnv(t *testing.T) {
	t.Setenv("NIM_API_KEY", "nvapi-secret-1234")
	p, err := FromName("nim", "https://integrate.api.nvidia.com")
	if err != nil {
		t.Fatalf("FromName nim: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://integrate.api.nvidia.com/v1/chat/completions", nil)
	p.PrepareRequest(req)

	if got := req.Header.Get("Authorization"); got != "Bearer nvapi-secret-1234" {
		t.Errorf("nim should inject Bearer token, got %q", got)
	}
	if got := req.Header.Get("User-Agent"); got != "modelgate/nim" {
		t.Errorf("nim should set default User-Agent, got %q", got)
	}
}

func TestNIM_DoesNotOverwriteUserAgent(t *testing.T) {
	t.Setenv("NIM_API_KEY", "k")
	p, _ := FromName("nim", "https://integrate.api.nvidia.com")
	req, _ := http.NewRequest(http.MethodPost, "https://integrate.api.nvidia.com/v1/chat/completions", nil)
	req.Header.Set("User-Agent", "client/1.2")
	p.PrepareRequest(req)
	if got := req.Header.Get("User-Agent"); got != "client/1.2" {
		t.Errorf("nim must not overwrite caller User-Agent, got %q", got)
	}
}

func TestNIM_MissingKey_LeavesAuthUnset(t *testing.T) {
	t.Setenv("NIM_API_KEY", "")
	p, _ := FromName("nim", "https://integrate.api.nvidia.com")
	req, _ := http.NewRequest(http.MethodPost, "https://integrate.api.nvidia.com/v1/chat/completions", nil)
	p.PrepareRequest(req)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("missing NIM_API_KEY should leave Authorization unset, got %q", got)
	}
}

func TestNIM_ForwardsNGCOrg(t *testing.T) {
	t.Setenv("NIM_API_KEY", "k")
	t.Setenv("NGC_ORG_ID", "org-42")
	p, _ := FromName("nim", "https://integrate.api.nvidia.com")
	req, _ := http.NewRequest(http.MethodPost, "https://integrate.api.nvidia.com/v1/chat/completions", nil)
	p.PrepareRequest(req)
	if got := req.Header.Get("NGC-Organization"); got != "org-42" {
		t.Errorf("expected NGC-Organization=org-42, got %q", got)
	}
}

func TestNIM_HealthCheck_HitsReadyPath(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("NIM_API_KEY", "hc-token")
	p, _ := FromName("nim", srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := p.HealthCheck(ctx, &http.Client{Timeout: time.Second}); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if gotPath != "/v1/health/ready" {
		t.Errorf("health path: want /v1/health/ready, got %q", gotPath)
	}
	if gotAuth != "Bearer hc-token" {
		t.Errorf("health auth: want Bearer hc-token, got %q", gotAuth)
	}
}

func TestNIM_HealthCheck_FailsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	p, _ := FromName("nim", srv.URL)
	err := p.HealthCheck(context.Background(), &http.Client{Timeout: time.Second})
	if err == nil {
		t.Error("expected health check to fail on 503")
	}
}

func TestGeneric_HealthCheck_TreatsNon5xxAsHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A bare / on an OpenAI-compatible server often 404s — that's fine.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, _ := FromName("generic", srv.URL)
	if err := p.HealthCheck(context.Background(), &http.Client{Timeout: time.Second}); err != nil {
		t.Errorf("404 on / should not fail generic health check: %v", err)
	}
}
