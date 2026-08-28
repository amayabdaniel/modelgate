//go:build k8s

package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFromKubeNIMService_PropagatesUID(t *testing.T) {
	kn := &KubeNIMService{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "llama3",
			Namespace: "nim",
			UID:       "cluster-assigned-uid",
		},
	}

	svc := FromKubeNIMService(kn)
	if svc.Metadata.UID != "cluster-assigned-uid" {
		t.Errorf("UID: want cluster-assigned-uid, got %q", svc.Metadata.UID)
	}
}

func TestToKubeNIMService_PropagatesUID(t *testing.T) {
	svc := &NIMService{
		Metadata: ObjectMeta{
			Name:      "llama3",
			Namespace: "nim",
			UID:       "cluster-assigned-uid",
		},
	}

	kn := ToKubeNIMService(svc)
	if string(kn.UID) != "cluster-assigned-uid" {
		t.Errorf("UID: want cluster-assigned-uid, got %q", kn.UID)
	}
}

// TestRoundTrip_FullyPopulatedNIMService_PreservesEveryField is the
// structural guard on ToKubeNIMService <-> FromKubeNIMService. The two
// converters are hand-written and must be kept in sync field-by-field:
// any Spec, Status, ObjectMeta, or Condition field that either one
// forgets silently gets zeroed as data crosses the k8s / pure-Go
// boundary the reconciler runs behind. Existing per-field tests only
// covered UID; a new field on NIMServiceSpec would go untested there.
//
// This test constructs an every-field-populated NIMService, runs it
// through both converters, and asserts full equality. Adding a field
// to any of the four types breaks this test unless both converters
// pass it through — the compile error / assertion failure IS the
// reminder to update the converters.
func TestRoundTrip_FullyPopulatedNIMService_PreservesEveryField(t *testing.T) {
	replicas := int32(3)
	orig := &NIMService{
		Kind:       "NIMService",
		APIVersion: "modelgate.dev/v1alpha1",
		Metadata: ObjectMeta{
			Name:       "llama3-8b",
			Namespace:  "nim",
			Generation: 42,
			UID:        "cluster-uid-abc",
			Labels: map[string]string{
				"app.kubernetes.io/name":       "llama3-8b",
				"app.kubernetes.io/managed-by": "modelgate",
			},
		},
		Spec: NIMServiceSpec{
			Image:         "nvcr.io/nim/meta/llama3-8b:1.0.0",
			Replicas:      &replicas,
			Model:         "llama3-8b-instruct",
			NGCSecretName: "ngc-key",
			GPURequest:    2,
			Port:          9000,
		},
		Status: NIMServiceStatus{
			ObservedGeneration: 41,
			ReadyReplicas:      2,
			Phase:              "Progressing",
			Conditions: []Condition{
				{Type: "SpecValid", Status: "True", Reason: "Applied"},
				{Type: "NGCKeyPresent", Status: "True", Reason: "Projected", Message: "secret ngc-key resolved"},
			},
		},
	}

	// Round-trip: NIMService -> KubeNIMService -> NIMService.
	back := FromKubeNIMService(ToKubeNIMService(orig))

	// Top-level fields.
	if back.Kind != orig.Kind {
		t.Errorf("Kind lost across round-trip: want %q, got %q", orig.Kind, back.Kind)
	}
	if back.APIVersion != orig.APIVersion {
		t.Errorf("APIVersion lost across round-trip: want %q, got %q", orig.APIVersion, back.APIVersion)
	}

	// ObjectMeta — every field. UID + Name + Namespace + Generation
	// have direct fields; Labels is a map that both converters copy.
	if back.Metadata.Name != orig.Metadata.Name {
		t.Errorf("Metadata.Name lost: want %q, got %q", orig.Metadata.Name, back.Metadata.Name)
	}
	if back.Metadata.Namespace != orig.Metadata.Namespace {
		t.Errorf("Metadata.Namespace lost: want %q, got %q", orig.Metadata.Namespace, back.Metadata.Namespace)
	}
	if back.Metadata.Generation != orig.Metadata.Generation {
		t.Errorf("Metadata.Generation lost: want %d, got %d", orig.Metadata.Generation, back.Metadata.Generation)
	}
	if back.Metadata.UID != orig.Metadata.UID {
		t.Errorf("Metadata.UID lost: want %q, got %q", orig.Metadata.UID, back.Metadata.UID)
	}
	if len(back.Metadata.Labels) != len(orig.Metadata.Labels) {
		t.Fatalf("Metadata.Labels count differs: want %d, got %d", len(orig.Metadata.Labels), len(back.Metadata.Labels))
	}
	for k, v := range orig.Metadata.Labels {
		if back.Metadata.Labels[k] != v {
			t.Errorf("Metadata.Labels[%q]: want %q, got %q", k, v, back.Metadata.Labels[k])
		}
	}

	// Spec — every field including the pointer-typed Replicas.
	if back.Spec.Image != orig.Spec.Image {
		t.Errorf("Spec.Image lost: want %q, got %q", orig.Spec.Image, back.Spec.Image)
	}
	if back.Spec.Model != orig.Spec.Model {
		t.Errorf("Spec.Model lost: want %q, got %q", orig.Spec.Model, back.Spec.Model)
	}
	if back.Spec.NGCSecretName != orig.Spec.NGCSecretName {
		t.Errorf("Spec.NGCSecretName lost: want %q, got %q", orig.Spec.NGCSecretName, back.Spec.NGCSecretName)
	}
	if back.Spec.GPURequest != orig.Spec.GPURequest {
		t.Errorf("Spec.GPURequest lost: want %d, got %d", orig.Spec.GPURequest, back.Spec.GPURequest)
	}
	if back.Spec.Port != orig.Spec.Port {
		t.Errorf("Spec.Port lost: want %d, got %d", orig.Spec.Port, back.Spec.Port)
	}
	if back.Spec.Replicas == nil {
		t.Fatal("Spec.Replicas: pointer lost across round-trip (would silently re-promote to defaulted 1)")
	}
	if *back.Spec.Replicas != *orig.Spec.Replicas {
		t.Errorf("Spec.Replicas value lost: want %d, got %d", *orig.Spec.Replicas, *back.Spec.Replicas)
	}

	// Status — including the Conditions slice which the KubeNIMService
	// DeepCopy handles by explicit-copy; the converter must preserve.
	if back.Status.ObservedGeneration != orig.Status.ObservedGeneration {
		t.Errorf("Status.ObservedGeneration lost: want %d, got %d", orig.Status.ObservedGeneration, back.Status.ObservedGeneration)
	}
	if back.Status.ReadyReplicas != orig.Status.ReadyReplicas {
		t.Errorf("Status.ReadyReplicas lost: want %d, got %d", orig.Status.ReadyReplicas, back.Status.ReadyReplicas)
	}
	if back.Status.Phase != orig.Status.Phase {
		t.Errorf("Status.Phase lost: want %q, got %q", orig.Status.Phase, back.Status.Phase)
	}
	if len(back.Status.Conditions) != len(orig.Status.Conditions) {
		t.Fatalf("Status.Conditions count differs: want %d, got %d", len(orig.Status.Conditions), len(back.Status.Conditions))
	}
	for i, c := range orig.Status.Conditions {
		got := back.Status.Conditions[i]
		if got.Type != c.Type || got.Status != c.Status || got.Reason != c.Reason || got.Message != c.Message {
			t.Errorf("Status.Conditions[%d] lost fields: want %+v, got %+v", i, c, got)
		}
	}
}

// TestRoundTrip_NilReplicas_StaysNil guards the specific pointer
// semantics that made "explicit scale-to-zero" possible: nil vs *int32
// distinguishes "omitted, default to 1" from "set to 0, don't default".
// A converter that dropped the pointer would break scale-to-zero
// silently. Companion to the full-round-trip test above; this one
// isolates the nil-pointer edge because the full test covers the
// non-nil path only.
func TestRoundTrip_NilReplicas_StaysNil(t *testing.T) {
	orig := &NIMService{
		Metadata: ObjectMeta{Name: "x", Namespace: "y"},
		Spec:     NIMServiceSpec{Image: "img", Replicas: nil},
	}
	back := FromKubeNIMService(ToKubeNIMService(orig))
	if back.Spec.Replicas != nil {
		t.Errorf("nil Replicas must survive round-trip as nil; got pointer to %d", *back.Spec.Replicas)
	}
}
