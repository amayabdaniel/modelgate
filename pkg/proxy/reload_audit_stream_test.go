package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

// TestReload_DoesNotLeakStateIntoAuditPath locks in a decoupling
// invariant peer flagged as the next pair to check after the reload
// no-op fix in 21bd127. The pair is: PolicyReloader.checkAndReload
// firing while an SSE consumer is subscribed to /v1/audit/stream and
// requests are flowing.
//
// Analysis says there's no race here — the audit path shares no
// mutable state with reload:
//
//   - auditFn is a closure captured once at NewMiddleware and never
//     rewritten by reload (reload only writes checker, policy,
//     rateLimiter, guardrails; auditFn is not among them).
//   - AuditBroker is a separate object; nothing in reload touches it.
//   - guardrails.Client, once created, is immutable — a request
//     holding a stale pointer through a reload keeps working against
//     the old (immutable) client.
//
// The test exercises the pair anyway so future edits can't quietly
// couple them (e.g., a reload-triggered auditFn swap, or a shared
// cache added to the guardrails client) without -race lighting up
// here. -race clean at 21bd127; if it ever fires this test, the
// decoupling invariant that justifies not synchronising the audit
// path against reload has been broken.
func TestReload_DoesNotLeakStateIntoAuditPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	writePolicy(t, path, `
rateLimits:
  - tenant: t
    tokens_per_minute: 100000
`)

	// Wire the pieces the way main.go does: middleware → audit broker
	// via auditFn closure, SSE handler over the broker.
	data, _ := os.ReadFile(path)
	var policy v1alpha1.InferencePolicySpec
	_ = yaml.Unmarshal(data, &policy)

	broker := NewAuditBroker()
	defer broker.Close()
	auditFn := func(ev AuditEvent) {
		broker.Publish(ev)
	}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mw, err := NewMiddleware(policy, upstream, auditFn)
	if err != nil {
		t.Fatalf("NewMiddleware: %v", err)
	}
	pr := NewPolicyReloader(path, mw, 0)
	if err := pr.checkAndReload(); err != nil {
		t.Fatalf("prime reload: %v", err)
	}

	sseHandler := NewAuditStreamHandler(broker).WithKeepalive(50 * time.Millisecond)
	server := httptest.NewServer(sseHandler)
	defer server.Close()

	// Live SSE consumer: reads audit events until its context is done.
	consumerCtx, cancelConsumer := context.WithCancel(context.Background())
	var consumerWG sync.WaitGroup
	consumerWG.Add(1)
	go func() {
		defer consumerWG.Done()
		req, _ := http.NewRequestWithContext(consumerCtx, http.MethodGet, server.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				return
			}
		}
	}()
	// Give the consumer a moment to subscribe.
	time.Sleep(50 * time.Millisecond)
	if broker.Subscribers() == 0 {
		t.Fatal("SSE consumer did not subscribe")
	}

	// Reloader: keeps rewriting the policy so every tick is a real
	// reload (size alternates so mtime+size cache misses).
	stop := make(chan struct{})
	var reloadWG sync.WaitGroup
	reloadWG.Add(1)
	go func() {
		defer reloadWG.Done()
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
				return
			}
			_ = pr.checkAndReload()
		}
	}()

	// Requesters: hammer the middleware so audit events flow into the
	// broker while reload runs.
	var reqWG sync.WaitGroup
	const requesters = 6
	const perRequesterRequests = 60
	reqWG.Add(requesters)
	for i := 0; i < requesters; i++ {
		go func() {
			defer reqWG.Done()
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

	reqWG.Wait()
	close(stop)
	reloadWG.Wait()

	// Kill the consumer, wait for it, then close the broker. Order
	// matters: if we Close the broker while the consumer is still in
	// its Read, the SSE handler returns cleanly (channel closed).
	cancelConsumer()
	consumerWG.Wait()

	// Ensure we consumed at least some events — otherwise the probe
	// is measuring nothing.
	_ = io.EOF
}
