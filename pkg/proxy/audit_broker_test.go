package proxy

import (
	"sync"
	"testing"
	"time"
)

func TestAuditBroker_PublishFansOutToAllSubscribers(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()

	s1 := b.Subscribe(8)
	s2 := b.Subscribe(8)

	delivered := b.Publish(AuditEvent{Tenant: "t1", Action: "allowed"})
	if delivered != 2 {
		t.Errorf("want 2 deliveries, got %d", delivered)
	}

	for i, ch := range []<-chan AuditEvent{s1.Events, s2.Events} {
		select {
		case ev := <-ch:
			if ev.Tenant != "t1" {
				t.Errorf("subscriber %d got wrong event: %+v", i, ev)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d did not receive event", i)
		}
	}
}

func TestAuditBroker_Unsubscribe_ClosesChannelAndStopsDelivery(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()
	s := b.Subscribe(4)

	b.Unsubscribe(s)
	// Subsequent publish should not deliver to s.
	delivered := b.Publish(AuditEvent{Tenant: "t1"})
	if delivered != 0 {
		t.Errorf("expected 0 deliveries after unsubscribe, got %d", delivered)
	}
	// Channel must be closed so consumers exit their range loop.
	if _, ok := <-s.Events; ok {
		t.Error("subscription channel must be closed after Unsubscribe")
	}
}

func TestAuditBroker_FullSubscriber_Drops_DoesNotBlockPublisher(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()
	sub := b.Subscribe(2) // tiny buffer

	// Fill the buffer plus 10 more events. Publisher must NOT block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 12; i++ {
			b.Publish(AuditEvent{Tenant: "burst"})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher stalled on a full subscriber — drop semantics broken")
	}

	if sub.Dropped() == 0 {
		t.Error("expected Dropped() > 0 after overflow")
	}
	if sub.Dropped()+int64(len(sub.Events)) != 12 {
		t.Errorf("dropped+buffered should equal total published 12, got %d+%d",
			sub.Dropped(), len(sub.Events))
	}
}

func TestAuditBroker_Close_ShutsDownAllSubscribers(t *testing.T) {
	b := NewAuditBroker()
	s1 := b.Subscribe(4)
	s2 := b.Subscribe(4)

	b.Close()

	if _, ok := <-s1.Events; ok {
		t.Error("s1 channel must close after Close")
	}
	if _, ok := <-s2.Events; ok {
		t.Error("s2 channel must close after Close")
	}
	// Further Subscribe yields an already-closed channel so consumers
	// exit cleanly without observing the broker state.
	s3 := b.Subscribe(4)
	if _, ok := <-s3.Events; ok {
		t.Error("post-close Subscribe must return closed channel")
	}
}

func TestAuditBroker_Subscribers_Count(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()

	if b.Subscribers() != 0 {
		t.Errorf("fresh broker should have 0 subscribers, got %d", b.Subscribers())
	}
	a := b.Subscribe(0)
	c := b.Subscribe(0)
	if b.Subscribers() != 2 {
		t.Errorf("want 2 subscribers, got %d", b.Subscribers())
	}
	b.Unsubscribe(a)
	if b.Subscribers() != 1 {
		t.Errorf("want 1 after unsubscribe, got %d", b.Subscribers())
	}
	_ = c
}

func TestAuditBroker_ConcurrentPublishersAndSubscribers(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()

	subs := make([]*AuditSubscription, 4)
	for i := range subs {
		subs[i] = b.Subscribe(2048)
	}

	const publishers = 8
	const perPublisher = 250

	var wg sync.WaitGroup
	wg.Add(publishers)
	for i := 0; i < publishers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perPublisher; j++ {
				b.Publish(AuditEvent{Tenant: "concurrent"})
			}
		}()
	}
	wg.Wait()

	// Every subscriber should have received roughly the full count;
	// allow drops since buffer < total. The key assertion is: no
	// panics, no deadlocks, no goroutine leaks. delivered+dropped per
	// subscriber must total exactly publishers*perPublisher.
	expected := int64(publishers * perPublisher)
	for i, s := range subs {
		got := int64(len(s.Events)) + s.Dropped()
		if got != expected {
			t.Errorf("subscriber %d: delivered+dropped = %d, want %d", i, got, expected)
		}
	}
}

func TestAuditBroker_UnsubscribeIdempotent(t *testing.T) {
	b := NewAuditBroker()
	defer b.Close()
	s := b.Subscribe(4)
	b.Unsubscribe(s)
	b.Unsubscribe(s) // must not panic
	b.Unsubscribe(nil)
}
