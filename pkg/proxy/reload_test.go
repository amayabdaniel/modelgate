package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

// TestPolicyReloader_ReplacesRateLimiter pins the fix for a silent
// hot-reload no-op: prior to buildFromPolicy landing, checkAndReload
// rebuilt only the checker and policy, so a change to policy.RateLimits
// on disk left the middleware using the original TokenBucket forever.
// An operator raising a rate limit expected the change to take effect
// on the next tick and got nothing. This asserts that after a reload
// the middleware's rateLimiter pointer has been replaced — the exact
// property that was previously false.
func TestPolicyReloader_ReplacesRateLimiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	writePolicy(t, path, `
rateLimits:
  - tenant: test
    tokens_per_minute: 100
`)
	mw := loadMiddlewareFromFile(t, path)
	pr := NewPolicyReloader(path, mw, 0)
	// Force the first stat to differ from zero-value so the file-changed
	// check triggers.
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	originalRL := mw.rateLimiter
	if originalRL == nil {
		t.Fatal("rateLimiter should be non-nil after initial reload with RateLimits present")
	}

	// Change the rate on disk. Rewrite entirely (not append) so the file
	// size differs too — checkAndReload also short-circuits when both
	// size and mtime match.
	writePolicy(t, path, `
rateLimits:
  - tenant: test
    tokens_per_minute: 5
`)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("second reload: %v", err)
	}

	if mw.rateLimiter == originalRL {
		t.Error("reload did not replace rateLimiter — a change to policy.RateLimits is silently a no-op until process restart, which is the exact bug this test locks the fix for")
	}
	if mw.rateLimiter == nil {
		t.Error("post-reload rateLimiter should be non-nil (new policy still has RateLimits)")
	}
}

// TestPolicyReloader_ReplacesGuardrailsClient pins the same fix for
// the guardrails endpoint: changing policy.Security.GuardrailsEndpoint
// on disk used to leave the middleware's guardrails client pointed at
// the old endpoint until process restart. Same shape as the rate
// limiter case — reload rebuilt only the checker.
func TestPolicyReloader_ReplacesGuardrailsClient(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	writePolicy(t, path, `
security:
  guardrails_endpoint: "http://127.0.0.1:9991"
`)
	mw := loadMiddlewareFromFile(t, path)
	pr := NewPolicyReloader(path, mw, 0)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("initial reload: %v", err)
	}
	originalGR := mw.guardrails
	if originalGR == nil {
		t.Fatal("guardrails client should be non-nil after initial reload with endpoint set")
	}

	writePolicy(t, path, `
security:
  guardrails_endpoint: "http://127.0.0.1:9992"
`)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("second reload: %v", err)
	}

	if mw.guardrails == originalGR {
		t.Error("reload did not replace guardrails client — a change to policy.Security.GuardrailsEndpoint is silently a no-op, so pointing the proxy at a new NeMo server via hot-reload does not take effect")
	}
	if mw.guardrails == nil {
		t.Error("post-reload guardrails should be non-nil (new policy still has an endpoint)")
	}
}

// TestPolicyReloader_TogglesGuardrailsOnOff completes the toggle
// coverage: adding an endpoint where there was none must enable
// guardrails, and removing an endpoint must disable it. Prior reload
// touched neither field, so both toggles were silent no-ops.
func TestPolicyReloader_TogglesGuardrailsOnOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Start with no endpoint.
	writePolicy(t, path, `security: {}`)
	mw := loadMiddlewareFromFile(t, path)
	pr := NewPolicyReloader(path, mw, 0)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("reload 1: %v", err)
	}
	if mw.guardrails != nil {
		t.Fatal("guardrails should be nil when policy has no endpoint")
	}

	// Add an endpoint.
	writePolicy(t, path, `
security:
  guardrails_endpoint: "http://127.0.0.1:9990"
`)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("reload 2: %v", err)
	}
	if mw.guardrails == nil {
		t.Error("adding guardrails_endpoint via reload must enable the guardrails client — was silently ignored before the fix")
	}

	// Remove the endpoint again.
	writePolicy(t, path, `security: {}`)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("reload 3: %v", err)
	}
	if mw.guardrails != nil {
		t.Error("removing guardrails_endpoint via reload must disable the guardrails client")
	}
}

// TestPolicyReloader_ConcurrentReloadWithRequests_NoRace exercises the
// exact production shape peer named: hot-reload happening while
// requests are in flight. The reloader rebuilds four fields under
// m.mu.Lock; ServeHTTP captures those four fields under m.mu.RLock at
// the top of the handler. -race must be clean, and each request must
// receive a non-zero response code — the primary assertion is the
// absence of panics, deadlocks, or races. Before the top-of-handler
// capture change, rateLimiter and guardrails were read lock-free
// while reload wrote them under lock; -race would fire here.
func TestPolicyReloader_ConcurrentReloadWithRequests_NoRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, `
rateLimits:
  - tenant: t
    tokens_per_minute: 10000
`)
	mw := loadMiddlewareFromFile(t, path)
	pr := NewPolicyReloader(path, mw, 0)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("prime reload: %v", err)
	}

	const requesters = 8
	const perRequesterRequests = 40

	var requestersWG sync.WaitGroup
	var reloadersWG sync.WaitGroup
	stop := make(chan struct{})

	// Reloader: rewrites the file with alternating rate limits so both
	// size and content change every iteration, defeating the reloader's
	// mtime+size cache and forcing a real rebuild on every call.
	reloadersWG.Add(1)
	go func() {
		defer reloadersWG.Done()
		for k := 0; ; k++ {
			select {
			case <-stop:
				return
			default:
			}
			body := "rateLimits:\n  - tenant: t\n    tokens_per_minute: "
			if k%2 == 0 {
				body += "12345\n"
			} else {
				body += "1234\n"
			}
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			_ = pr.checkAndReload()
		}
	}()

	requestersWG.Add(requesters)
	for i := 0; i < requesters; i++ {
		go func() {
			defer requestersWG.Done()
			for k := 0; k < perRequesterRequests; k++ {
				rr := httptest.NewRecorder()
				req := chatRequest(t, "m", "hi")
				req.Header.Set("X-Tenant", "t")
				mw.ServeHTTP(rr, req)
				if rr.Code == 0 {
					t.Errorf("empty response code")
					return
				}
			}
		}()
	}

	requestersWG.Wait()
	close(stop)
	reloadersWG.Wait()
}

// TestPolicyReloader_ChangesTakeEffectOnNextRequest verifies the
// observable behaviour — beyond identity — of a rate-limit change:
// after reload, a tenant that would be allowed under the old rate
// limit is blocked under the new tight one. This is what "reload
// applies the policy" actually means to an operator.
func TestPolicyReloader_ChangesTakeEffectOnNextRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")

	// Loose limit: ~2500 tokens/min burst, easily accommodates a
	// modest prompt.
	writePolicy(t, path, `
rateLimits:
  - tenant: t
    tokens_per_minute: 5000
`)
	mw := loadMiddlewareFromFile(t, path)
	pr := NewPolicyReloader(path, mw, 0)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("initial reload: %v", err)
	}

	// Request under the loose limit — should be allowed.
	rr := httptest.NewRecorder()
	req := chatRequest(t, "m", strings.Repeat("a", 40)) // ~10 tokens
	req.Header.Set("X-Tenant", "t")
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("under loose limit, expected 200, got %d", rr.Code)
	}

	// Tighten to 1 token/min with 2-token burst — any real prompt now
	// exceeds it.
	writePolicy(t, path, `
rateLimits:
  - tenant: t
    tokens_per_minute: 1
`)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("tighten reload: %v", err)
	}

	rr = httptest.NewRecorder()
	req = chatRequest(t, "m", strings.Repeat("a", 400)) // ~100 tokens, well over 2-token burst
	req.Header.Set("X-Tenant", "t")
	mw.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("after reload to tight limit, expected 429, got %d — before the fix reload silently kept the loose limiter in place",
			rr.Code)
	}
}

// writePolicy writes YAML to `path` and defeats mtime resolution
// collisions on fast filesystems by asserting the write succeeded;
// tests separated by a reload call use content differences (not just
// timestamps) so the size-or-mtime cache check fires reliably.
func writePolicy(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}

// loadMiddlewareFromFile parses a policy file and constructs a
// Middleware with a stub upstream that returns 200 — matches the shape
// tests need for reload identity checks without depending on other
// helpers in this package. auditFn is nil because these tests observe
// state directly on the middleware struct.
func loadMiddlewareFromFile(t *testing.T, path string) *Middleware {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var policy v1alpha1.InferencePolicySpec
	if err := yaml.Unmarshal(data, &policy); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mw, err := NewMiddleware(policy, upstream, nil)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	return mw
}

// Ensure bytes.Reader is used elsewhere in this package's tests.
var _ = bytes.NewReader
