package proxy

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/amayabdaniel/modelgate/pkg/security"
)

// TestAuditEvent_WireKeySet is a cross-repo drift guard.
//
// AuditEvent's JSON is consumed by gpudab-server as a *mirror type*
// (`AuditEventWire` in internal/source/cuanomaly/audit_consumer.go)
// that lives in a different repo and cannot share a Go type with this
// one. When someone adds a field here without updating the mirror,
// gpudab silently drops the data — the historical Position-in-
// violations gap was found exactly this way.
//
// This test doesn't reach across the repo boundary (it can't); it
// locks in the exact top-level and violation-item keys AuditEvent
// serializes to. Any change to the wire — a new field, a renamed json
// tag, dropping omitempty — fails here at the source of the change,
// forcing the author to update the expected sets AND (via the failure
// message pointing at the sibling file) update gpudab-server's
// AuditEventWire.
func TestAuditEvent_WireKeySet(t *testing.T) {
	ev := AuditEvent{
		Model:               "m",
		Tenant:              "t",
		Action:              "blocked",
		Reason:              "r",
		Violations:          []security.Violation{{Rule: "r", Severity: "s", Message: "msg", Position: 1}},
		PromptLength:        1,
		PromptHash:          "h",
		ProcessingLatencyMs: 1,
	}

	// Expected top-level keys (JSON tags on AuditEvent).
	wantTop := []string{
		"model", "tenant", "action", "reason", "violations",
		"prompt_length", "prompt_hash", "processing_latency_ms",
	}

	// Expected keys inside each violation item. security.Violation has
	// NO json tags, so Go's encoder emits its Go field names verbatim
	// (capitalized). gpudab decodes case-insensitively, which is why
	// its lowercase tags happen to work — a fragile-but-currently-
	// correct alignment locked in by this contract.
	wantViol := []string{"Rule", "Severity", "Message", "Position"}

	auditEventSibling := "AuditEventWire in gpudab-server/internal/source/cuanomaly/audit_consumer.go"
	assertJSONKeys(t, ev, wantTop, "top-level AuditEvent", "AuditEvent", auditEventSibling)
	assertJSONKeys(t, ev.Violations[0], wantViol, "violation item", "security.Violation", auditEventSibling)
}

// assertJSONKeys marshals `v` and checks its top-level object key set
// equals `want`. sibling names the mirror type + file the caller must
// keep in lockstep, so a drift failure prints an actionable pointer
// instead of a generic diff.
func assertJSONKeys(t *testing.T, v any, want []string, what, typeName, sibling string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", what, err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("re-decode %s: %v", what, err)
	}
	gotKeys := make([]string, 0, len(got))
	for k := range got {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	wantCopy := append([]string(nil), want...)
	sort.Strings(wantCopy)

	if !stringSlicesEqual(gotKeys, wantCopy) {
		t.Errorf(`%s wire shape drifted. Type: %s
  got:  %v
  want: %v
If you changed the wire format here, also update the mirror type
%s
and its own contract test — the two repos must stay in sync or the
consumer silently drops the new field (case-insensitive JSON decode
masks most divergence until a field goes entirely missing).`,
			what, typeName, gotKeys, wantCopy, sibling)
	}
}

// TestAuditStreamStats_WireKeySet is the sibling drift guard for the
// broker-health block modelgate emits on /stats.
//
// gpudab-server parses this via a *mirror type* (ModelgateAuditStreamStats
// in internal/source/gpucast.go) that lives in a different repo and
// can't share a Go type with this one. When someone adds a field here
// without updating the mirror, gpudab silently drops it. Same shape of
// gap the AuditEvent contract test above closes.
func TestAuditStreamStats_WireKeySet(t *testing.T) {
	s := AuditStreamStats{Subscribers: 3, TotalDropped: 42}
	want := []string{"subscribers", "total_dropped"}
	sibling := "ModelgateAuditStreamStats in gpudab-server/internal/source/gpucast.go"
	assertJSONKeys(t, s, want, "AuditStreamStats", "AuditStreamStats", sibling)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
