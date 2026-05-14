package proxy

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// readSSEEvent reads frames from an SSE response body until the first
// `event: audit` is observed or the deadline elapses. Returns the data
// payload (everything after `data: `) for the first audit event seen.
func readSSEEvent(t *testing.T, body *bufio.Reader, deadline time.Duration) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		var inAudit bool
		for {
			line, err := body.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "event: audit"):
				inAudit = true
			case inAudit && strings.HasPrefix(line, "data: "):
				got <- strings.TrimPrefix(line, "data: ")
				return
			case line == "":
				inAudit = false
			}
		}
	}()
	select {
	case s := <-got:
		return s
	case <-time.After(deadline):
		t.Fatal("timed out waiting for SSE audit event")
		return ""
	}
}

func TestAuditStream_DeliversPublishedEvents(t *testing.T) {
	broker := NewAuditBroker()
	defer broker.Close()
	h := NewAuditStreamHandler(broker).WithKeepalive(0)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("want event-stream content-type, got %q", ct)
	}

	// Give the handler a moment to register its subscription.
	time.Sleep(50 * time.Millisecond)

	broker.Publish(AuditEvent{Tenant: "t1", Model: "llama3", Action: "allowed"})

	body := bufio.NewReader(resp.Body)
	payload := readSSEEvent(t, body, 2*time.Second)
	if !strings.Contains(payload, `"tenant":"t1"`) {
		t.Errorf("payload missing tenant: %s", payload)
	}
	if !strings.Contains(payload, `"action":"allowed"`) {
		t.Errorf("payload missing action: %s", payload)
	}
}

func TestAuditStream_RetryHintEmittedFirst(t *testing.T) {
	broker := NewAuditBroker()
	defer broker.Close()
	h := NewAuditStreamHandler(broker).WithKeepalive(0)

	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body := bufio.NewReader(resp.Body)
	// First line of the stream should be the retry hint so reconnecting
	// EventSource clients honor the 3s backoff.
	line, _ := body.ReadString('\n')
	if !strings.HasPrefix(line, "retry:") {
		t.Errorf("expected SSE retry hint first, got %q", line)
	}
}

func TestAuditStream_SubscriberLimitReturns503(t *testing.T) {
	broker := NewAuditBroker()
	defer broker.Close()
	// Limit of 1; the first connection holds the slot, the second
	// should be rejected.
	h := NewAuditStreamHandler(broker).WithKeepalive(0).WithSubscriberLimit(1)

	srv := httptest.NewServer(h)
	defer srv.Close()

	// First connection — keep it open via a context we don't cancel
	// until cleanup.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	req1, _ := http.NewRequestWithContext(ctx1, http.MethodGet, srv.URL, nil)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first conn should be 200, got %d", resp1.StatusCode)
	}

	// Wait for the subscriber to register.
	for i := 0; i < 100 && broker.Subscribers() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	// Second connection should be rejected with 503.
	resp2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("over-limit connection should be 503, got %d", resp2.StatusCode)
	}
}

func TestAuditStream_ClientDisconnectReleasesSubscription(t *testing.T) {
	broker := NewAuditBroker()
	defer broker.Close()
	h := NewAuditStreamHandler(broker).WithKeepalive(0)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for subscription.
	for i := 0; i < 100 && broker.Subscribers() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if broker.Subscribers() != 1 {
		t.Fatal("subscription did not register")
	}

	// Cancel the request — server side should see the context done and
	// unsubscribe.
	cancel()
	resp.Body.Close()

	// Give the goroutine a moment to react.
	for i := 0; i < 100 && broker.Subscribers() != 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if broker.Subscribers() != 0 {
		t.Errorf("disconnect did not release subscription; %d still active", broker.Subscribers())
	}
}

func TestAuditStream_KeepaliveFramesEmitted(t *testing.T) {
	broker := NewAuditBroker()
	defer broker.Close()
	h := NewAuditStreamHandler(broker).WithKeepalive(50 * time.Millisecond)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body := bufio.NewReader(resp.Body)
	// Drain retry hint first.
	_, _ = body.ReadString('\n')
	_, _ = body.ReadString('\n')

	// Look for at least one keepalive within 500ms.
	got := make(chan string, 1)
	go func() {
		for i := 0; i < 50; i++ {
			line, err := body.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, ": keepalive") {
				got <- line
				return
			}
		}
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no keepalive frame within 2s")
	}
}
