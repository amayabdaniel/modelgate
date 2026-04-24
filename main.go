package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/pkg/provider"
	"github.com/amayabdaniel/modelgate/pkg/proxy"
	"gopkg.in/yaml.v3"
)

func main() {
	addr := flag.String("listen", ":8080", "address to listen on")
	policyFile := flag.String("policy", "policy.yaml", "path to inference policy file")
	backendURL := flag.String("backend", "", "backend LLM API URL (e.g., http://localhost:8000)")
	providerName := flag.String("provider", "generic", "upstream provider: generic, nim, openai, ollama, vllm")
	flag.Parse()

	if *backendURL == "" {
		log.Fatal("modelgate: --backend is required (e.g., --backend=http://vllm:8000)")
	}

	// Load policy
	policy, err := loadPolicy(*policyFile)
	if err != nil {
		log.Fatalf("modelgate: loading policy: %v", err)
	}
	log.Printf("modelgate: loaded policy from %s", *policyFile)
	log.Printf("modelgate: %d budget rules, %d rate limits, injection protection=%t, pii redaction=%t",
		len(policy.Budgets), len(policy.RateLimits),
		policy.Security.PromptInjectionProtection, policy.Security.PIIRedaction)

	// Resolve provider (generic, nim, ...). Provider encapsulates upstream
	// auth header conventions and the health probe path.
	prov, err := provider.FromName(*providerName, *backendURL)
	if err != nil {
		log.Fatalf("modelgate: provider: %v", err)
	}
	log.Printf("modelgate: provider=%s backend=%s", prov.Name(), prov.Target().String())

	// One-shot readiness probe at startup so misconfigured NIM keys fail
	// loud instead of appearing only on the first real request.
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 3*time.Second)
	if err := prov.HealthCheck(probeCtx, &http.Client{Timeout: 3 * time.Second}); err != nil {
		log.Printf("modelgate: warning: upstream not ready at startup: %v", err)
	}
	cancelProbe()

	// Reverse proxy with provider-aware director — PrepareRequest injects
	// auth headers, rewrites paths, etc. We wrap the default director so
	// scheme/host rewriting still happens first.
	reverseProxy := httputil.NewSingleHostReverseProxy(prov.Target())
	baseDirector := reverseProxy.Director
	reverseProxy.Director = func(r *http.Request) {
		baseDirector(r)
		prov.PrepareRequest(r)
	}

	// Stats tracking
	stats := proxy.NewStats()
	stats.SetProvider(prov.Name(), prov.Target().String())

	// Audit logging with stats integration
	auditFn := func(event proxy.AuditEvent) {
		data, _ := json.Marshal(event)
		log.Printf("modelgate: audit: %s", string(data))

		switch event.Action {
		case "allowed":
			stats.RecordAllowed(event.Tenant)
		case "blocked":
			rule := "unknown"
			if len(event.Violations) > 0 {
				rule = event.Violations[0].Rule
			} else if event.Reason == "PII detected in prompt" {
				rule = "pii_redaction"
			} else if event.Reason == "Rate limit exceeded" {
				stats.RecordRateLimited(event.Tenant)
				return
			}
			stats.RecordBlocked(event.Tenant, rule)
		}
	}

	// Create security middleware
	mw, err := proxy.NewMiddleware(*policy, reverseProxy, auditFn)
	if err != nil {
		log.Fatalf("modelgate: creating middleware: %v", err)
	}

	// Start policy hot-reloader (watches file every 5 seconds)
	reloader := proxy.NewPolicyReloader(*policyFile, mw, 5*time.Second)
	reloader.Start()
	log.Println("modelgate: policy hot-reload enabled")

	// Health + stats endpoints
	mux := http.NewServeMux()
	mux.Handle("/stats", stats.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// readyz reflects upstream readiness so orchestrators only send
		// traffic once the backing provider actually responds. A 503 here
		// is the correct signal for a Kubernetes readiness probe.
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := prov.HealthCheck(ctx, &http.Client{Timeout: 2 * time.Second}); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, "upstream not ready: %v\n", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	// All other traffic goes through security middleware → backend
	mux.Handle("/", mw)

	log.Printf("modelgate: proxying to %s via provider=%s", *backendURL, prov.Name())
	log.Printf("modelgate: listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func loadPolicy(path string) (*v1alpha1.InferencePolicySpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var policy v1alpha1.InferencePolicySpec
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validating %s: %w", path, err)
	}

	return &policy, nil
}
