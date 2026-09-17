package proxy

import (
	"sync"
	"testing"
)

// TestAuditBroker_UnsubscribeConcurrentWithClose_NoRace pins the fix
// for a data race that had been latent since the broker landed: a
// prior AuditSubscription carried an unlocked back-pointer to its
// owning broker, and Unsubscribe read it lock-free as a fast-path
// guard while Close wrote it under lock. Under -race with concurrent
// Close + Unsubscribe on the same subscription — the exact shape of
// server shutdown while a handler's defer Unsubscribe is firing —
// this reported a data race at audit_broker.go:79/125.
//
// The bug shipped silently because no existing test contended those
// two operations on the same subscription; each was covered
// individually. This test would have caught it from the start and
// exists to catch a regression if someone reintroduces a lock-free
// back-pointer or any other unsynchronised access to per-subscription
// state during a concurrent Close.
func TestAuditBroker_UnsubscribeConcurrentWithClose_NoRace(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		b := NewAuditBroker()
		subs := make([]*AuditSubscription, 16)
		for i := range subs {
			subs[i] = b.Subscribe(4)
		}
		var wg sync.WaitGroup
		wg.Add(len(subs) + 1)
		for _, sub := range subs {
			sub := sub
			go func() {
				defer wg.Done()
				b.Unsubscribe(sub)
			}()
		}
		go func() {
			defer wg.Done()
			b.Close()
		}()
		wg.Wait()
	}
}

// TestAuditBroker_UnsubscribePostCloseSubscription pins the second
// corner of the same fix: a subscription returned from a post-Close
// Subscribe (whose channel is already closed and which was never
// added to b.subs) must survive Unsubscribe without panicking on a
// double close(chan). The subs-map membership check is the sole
// gate; if a future edit adds back-channel state to the subscription
// this test locks in that Unsubscribe still no-ops cleanly.
func TestAuditBroker_UnsubscribePostCloseSubscription(t *testing.T) {
	b := NewAuditBroker()
	b.Close()

	sub := b.Subscribe(4)
	// Channel must already be closed by post-close Subscribe.
	if _, ok := <-sub.Events; ok {
		t.Fatal("post-close Subscribe must return closed channel")
	}
	// Unsubscribe on this sub must be a no-op — no panic on
	// double-close, no map mutation.
	b.Unsubscribe(sub)
	b.Unsubscribe(sub)
}
