package proxy

import (
	"sync"
	"sync/atomic"
)

// AuditBroker fans out AuditEvents from the middleware to any number of
// subscribers (typically SSE clients consuming /v1/audit/stream).
//
// Design constraints:
//
//   - The proxy hot path must never block. Subscribers with full buffers
//     get *dropped* events, not stalled. A counter on each subscription
//     records dropped count so the consumer can decide what to do.
//   - Publishing is goroutine-safe under high request concurrency. We
//     use an RWMutex: many concurrent publishes (read-lock the
//     subscriber map), occasional subscribe/unsubscribe (write-lock).
//   - Subscribers are channel-based; consumers receive via Go's normal
//     channel semantics. Closing the channel signals shutdown.
//
// Buffer size is tunable per subscription. 1024 is a sane default —
// roughly 30 seconds at 30 audit events/sec, enough for an SSE client
// to recover from a transient slow read.
type AuditBroker struct {
	mu      sync.RWMutex
	subs    map[*AuditSubscription]struct{}
	closed  bool

	// totalDropped is a broker-lifetime counter, unlike each
	// AuditSubscription's own dropped tally: a subscription's counter is
	// discarded on Unsubscribe (e.g. every gpudab reconnect), so it can
	// never show operators drops that happened under a prior consumer.
	// This one only grows, giving /stats a "have we ever fallen behind
	// any consumer" signal independent of who is currently attached.
	totalDropped atomic.Int64
}

// AuditSubscription is one consumer's view into the broker. The Events
// channel is the read side; the consumer must drain it or accept that
// over-quota events are dropped (Dropped() reports the running count).
//
// Membership in a broker is tracked exclusively by the broker's own
// subs map, guarded by AuditBroker.mu — the subscription itself carries
// no back-pointer. A prior design cached the owning broker on the
// subscription as a lock-free fast path for redundant Unsubscribe
// calls; that read raced with Close's write under -race (a real bug,
// not just detector noise: Close and a defer-Unsubscribe on shutdown
// touch the same field with no synchronization). Removing the field
// makes redundant-unsubscribe cost one map lookup under the lock
// instead of a lock-free branch, which is orders of magnitude below
// the SSE fan-out cost that dominates this path.
type AuditSubscription struct {
	Events chan AuditEvent

	dropped atomic.Int64
}

// NewAuditBroker constructs an empty broker.
func NewAuditBroker() *AuditBroker {
	return &AuditBroker{subs: map[*AuditSubscription]struct{}{}}
}

// Subscribe returns a new subscription with a buffered channel. The
// caller MUST eventually call Unsubscribe (typically on disconnect) to
// release the underlying channel and remove the subscriber from the
// broker's map. bufferSize <= 0 falls back to 1024.
func (b *AuditBroker) Subscribe(bufferSize int) *AuditSubscription {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	sub := &AuditSubscription{
		Events: make(chan AuditEvent, bufferSize),
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		close(sub.Events)
		return sub
	}
	b.subs[sub] = struct{}{}
	return sub
}

// Unsubscribe removes the subscription and closes its channel. Safe to
// call multiple times and safe on a subscription that came back from a
// post-Close Subscribe: the lookup on b.subs is the sole source of
// truth for "still active" and returns cleanly when the entry is
// absent, so double-close of the channel is impossible.
func (b *AuditBroker) Unsubscribe(sub *AuditSubscription) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[sub]; !ok {
		return
	}
	delete(b.subs, sub)
	close(sub.Events)
}

// Publish delivers an event to all subscribers. Subscribers with full
// buffers see Dropped() increment; the proxy itself never blocks.
// Returns the number of subscribers that received the event so callers
// can detect "broker has zero listeners" without inspecting internals.
func (b *AuditBroker) Publish(ev AuditEvent) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	delivered := 0
	for sub := range b.subs {
		select {
		case sub.Events <- ev:
			delivered++
		default:
			sub.dropped.Add(1)
			b.totalDropped.Add(1)
		}
	}
	return delivered
}

// Close shuts down the broker: every subscriber's channel is closed and
// further Subscribe calls return a closed-channel subscription so
// pending readers exit immediately. Publish after Close is a silent
// no-op (no subscribers to deliver to).
func (b *AuditBroker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for sub := range b.subs {
		close(sub.Events)
	}
	b.subs = map[*AuditSubscription]struct{}{}
}

// Subscribers reports the current count. Useful for /healthz output and
// "is anyone listening?" branches in tests.
func (b *AuditBroker) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Dropped returns the running tally of events this subscription
// missed because its buffer was full. Consumers can include this in
// SSE keepalive frames so downstream systems can detect gaps.
func (s *AuditSubscription) Dropped() int64 { return s.dropped.Load() }

// TotalDropped returns the broker's lifetime count of events dropped
// across every subscription it has ever fanned out to, including ones
// that have since unsubscribed. See the totalDropped field comment for
// why this differs from summing current subscriptions' Dropped().
func (b *AuditBroker) TotalDropped() int64 { return b.totalDropped.Load() }
