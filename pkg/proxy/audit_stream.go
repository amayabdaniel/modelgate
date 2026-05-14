package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AuditStreamHandler exposes a Server-Sent Events feed of AuditEvents
// over HTTP. Each request mutation by the proxy (allowed, blocked,
// rate-limited) becomes one `data:` line in the stream.
//
// SSE was chosen over websockets because:
//
//   - Pure HTTP, no upgrade dance — works through any HTTP proxy and
//     reverse-proxy that handles standard streaming bodies.
//   - Reconnection semantics are baked into EventSource. Consumers
//     (gpudab's Morpheus backend) get retries for free.
//   - The data flow is one-way; we never need client→server frames.
//
// The handler also emits periodic `:keepalive` comments so corporate
// proxies that idle-close long HTTP connections see traffic and stay
// open. Without these, the stream would silently drop every ~60s.
type AuditStreamHandler struct {
	broker          *AuditBroker
	keepaliveEvery  time.Duration
	subscriberLimit int
}

// NewAuditStreamHandler builds a handler over the supplied broker.
// keepaliveEvery <= 0 disables periodic keepalive frames (only useful
// in tests where the connection lives <1s).
func NewAuditStreamHandler(broker *AuditBroker) *AuditStreamHandler {
	return &AuditStreamHandler{
		broker:          broker,
		keepaliveEvery:  20 * time.Second,
		subscriberLimit: 16,
	}
}

// WithKeepalive overrides the keepalive cadence. Returns the handler.
func (h *AuditStreamHandler) WithKeepalive(d time.Duration) *AuditStreamHandler {
	h.keepaliveEvery = d
	return h
}

// WithSubscriberLimit caps the number of concurrent SSE consumers. The
// broker has no inherent cap; the audit stream is sensitive, so we
// limit fan-out to deter accidental fan-bombs. Default 16; 0 disables.
func (h *AuditStreamHandler) WithSubscriberLimit(n int) *AuditStreamHandler {
	h.subscriberLimit = n
	return h
}

// ServeHTTP runs the SSE conversation. The handler returns when:
//   - the client disconnects (request Context done),
//   - the broker is Close()'d (subscription channel closes), or
//   - a write to the response body fails (the client went away).
func (h *AuditStreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.subscriberLimit > 0 && h.broker.Subscribers() >= h.subscriberLimit {
		http.Error(w, "audit stream subscriber limit reached", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// http.ResponseWriter not flushable means the server stack does
		// not support streaming — fail fast rather than buffer forever.
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx response buffering
	w.WriteHeader(http.StatusOK)

	// SSE retry hint: ask reconnecting clients to wait 3s.
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()

	sub := h.broker.Subscribe(1024)
	defer h.broker.Unsubscribe(sub)

	var keepalive <-chan time.Time
	if h.keepaliveEvery > 0 {
		t := time.NewTicker(h.keepaliveEvery)
		defer t.Stop()
		keepalive = t.C
	}

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Events:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				// Skip malformed events rather than tear down the
				// stream; a single bad event must not silence the rest.
				continue
			}
			if _, err := fmt.Fprintf(w, "event: audit\ndata: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		case <-keepalive:
			// Emit dropped-count so consumers can detect gaps even
			// during quiet periods.
			if _, err := fmt.Fprintf(w, ": keepalive dropped=%d\n\n", sub.Dropped()); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
