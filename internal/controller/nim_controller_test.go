package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
)

// fakeClient is an in-memory Client stand-in used across the reconciler
// tests. It tracks Create/Update calls so assertions can inspect what
// the reconciler actually asked the cluster to do.
type fakeClient struct {
	svc            *v1alpha1.NIMService
	deployment     *Deployment
	createOrUpdate []Deployment
	statusUpdates  []v1alpha1.NIMServiceStatus
	getSvcErr      error
	updateErr      error
}

func (f *fakeClient) GetNIMService(_ context.Context, _, _ string) (*v1alpha1.NIMService, error) {
	return f.svc, f.getSvcErr
}

func (f *fakeClient) UpdateNIMServiceStatus(_ context.Context, svc *v1alpha1.NIMService) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.statusUpdates = append(f.statusUpdates, svc.Status)
	f.svc = svc
	return nil
}

func (f *fakeClient) GetDeployment(_ context.Context, _, _ string) (*Deployment, error) {
	if f.deployment == nil {
		return &Deployment{}, nil
	}
	return f.deployment, nil
}

func (f *fakeClient) CreateOrUpdateDeployment(_ context.Context, d *Deployment) error {
	f.createOrUpdate = append(f.createOrUpdate, *d)
	// Preserve observed-state fields from any previously-installed deployment;
	// a real cluster does not wipe ready replica counts on Apply.
	merged := *d
	if f.deployment != nil {
		merged.ObservedReadyReplicas = f.deployment.ObservedReadyReplicas
	}
	f.deployment = &merged
	return nil
}

func newSvc(spec v1alpha1.NIMServiceSpec) *v1alpha1.NIMService {
	return &v1alpha1.NIMService{
		Kind:       "NIMService",
		APIVersion: "modelgate.dev/v1alpha1",
		Metadata: v1alpha1.ObjectMeta{
			Name:       "llama3",
			Namespace:  "nim",
			Generation: 7,
		},
		Spec: spec,
	}
}

func int32Ptr(v int32) *int32 { return &v }

func TestReconcile_MaterializesDeploymentAndStatus(t *testing.T) {
	fc := &fakeClient{
		svc: newSvc(v1alpha1.NIMServiceSpec{
			Image:         "nvcr.io/nim/meta/llama3-8b:1.0.0",
			Replicas:      int32Ptr(2),
			Model:         "llama3-8b",
			NGCSecretName: "ngc-key",
		}),
		deployment: &Deployment{ObservedReadyReplicas: 2},
	}

	r := NewReconciler(fc)
	if err := r.Reconcile(context.Background(), "nim", "llama3"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(fc.createOrUpdate) != 1 {
		t.Fatalf("expected one CreateOrUpdateDeployment call, got %d", len(fc.createOrUpdate))
	}
	d := fc.createOrUpdate[0]
	if d.Image != "nvcr.io/nim/meta/llama3-8b:1.0.0" {
		t.Errorf("image: %q", d.Image)
	}
	if d.Replicas != 2 {
		t.Errorf("replicas: %d", d.Replicas)
	}
	if d.GPURequest != 1 {
		t.Errorf("GPU request default should be 1, got %d", d.GPURequest)
	}
	if d.Port != 8000 {
		t.Errorf("port default should be 8000, got %d", d.Port)
	}
	if got := d.Env["NGC_API_KEY"]; got != "secret:ngc-key" {
		t.Errorf("NGC_API_KEY env: want secret:ngc-key, got %q", got)
	}
	if d.Labels["app.kubernetes.io/managed-by"] != "modelgate" {
		t.Errorf("managed-by label missing")
	}

	if fc.svc.Status.Phase != "Ready" {
		t.Errorf("phase: want Ready, got %s", fc.svc.Status.Phase)
	}
	if fc.svc.Status.ObservedGeneration != 7 {
		t.Errorf("observedGeneration: want 7, got %d", fc.svc.Status.ObservedGeneration)
	}
	if fc.svc.Status.ReadyReplicas != 2 {
		t.Errorf("readyReplicas: want 2, got %d", fc.svc.Status.ReadyReplicas)
	}

	if !hasCondition(fc.svc.Status.Conditions, "SpecValid", "True") {
		t.Error("missing SpecValid=True condition")
	}
	if !hasCondition(fc.svc.Status.Conditions, "NGCKeyPresent", "True") {
		t.Error("missing NGCKeyPresent=True condition")
	}
}

func TestReconcile_MissingNGCSecret_FlagsCondition(t *testing.T) {
	fc := &fakeClient{
		svc: newSvc(v1alpha1.NIMServiceSpec{
			Image: "nvcr.io/nim/meta/llama3-8b:1.0.0",
		}),
		deployment: &Deployment{ObservedReadyReplicas: 1},
	}

	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "llama3"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := fc.createOrUpdate[0].Env["NGC_API_KEY"]; ok {
		t.Error("NGC_API_KEY should not be projected when ngcSecretName is empty")
	}
	if !hasCondition(fc.svc.Status.Conditions, "NGCKeyPresent", "False") {
		t.Error("expected NGCKeyPresent=False condition when secret is missing")
	}
}

func TestReconcile_ProgressingPhase_WhenReplicasNotReady(t *testing.T) {
	fc := &fakeClient{
		svc: newSvc(v1alpha1.NIMServiceSpec{
			Image:    "nvcr.io/nim/meta/llama3-8b:1.0.0",
			Replicas: int32Ptr(3),
		}),
		deployment: &Deployment{ObservedReadyReplicas: 1},
	}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "llama3"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fc.svc.Status.Phase != "Progressing" {
		t.Errorf("phase: want Progressing, got %s", fc.svc.Status.Phase)
	}
}

func TestReconcile_PendingPhase_WhenZeroReady(t *testing.T) {
	fc := &fakeClient{
		svc:        newSvc(v1alpha1.NIMServiceSpec{Image: "x", Replicas: int32Ptr(1)}),
		deployment: &Deployment{ObservedReadyReplicas: 0},
	}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "x"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if fc.svc.Status.Phase != "Pending" {
		t.Errorf("phase: want Pending, got %s", fc.svc.Status.Phase)
	}
}

// TestDerivePhase_ScaleToZeroInProgress guards the specific case the
// old derivePhase got wrong: desired=0 was hardcoded to "Ready"
// regardless of ready count, so a scale-down that hadn't yet shut down
// pods (which are still holding GPU allocations) showed "Ready" while
// resources were still occupied. Operators reading `kubectl get nim`
// would think the scale-down completed when it hadn't.
func TestDerivePhase_ScaleToZeroInProgress(t *testing.T) {
	if got := derivePhase(0, 5); got != "Progressing" {
		t.Errorf("desired=0 ready=5 (pods still running mid-shutdown) must be Progressing, got %q", got)
	}
	// The already-quiesced case must still be Ready.
	if got := derivePhase(0, 0); got != "Ready" {
		t.Errorf("desired=0 ready=0 (fully scaled down) must be Ready, got %q", got)
	}
}

// TestDerivePhase_ScaleDownInProgress guards the mid-scale-down case:
// the old default branch returned "Ready" whenever the switch fell
// through, which included the `ready > desired` case where extra
// replicas were still running and holding GPU allocations after the
// operator scaled down.
func TestDerivePhase_ScaleDownInProgress(t *testing.T) {
	if got := derivePhase(3, 5); got != "Progressing" {
		t.Errorf("desired=3 ready=5 (extra replicas still holding GPUs) must be Progressing, got %q", got)
	}
}

// TestDerivePhase_KnownGoodCases locks in every phase the reconciler
// is supposed to report so a future rewrite can't silently regress the
// cases the bug fix depends on maintaining.
func TestDerivePhase_KnownGoodCases(t *testing.T) {
	cases := []struct {
		desired, ready int32
		want           string
	}{
		{desired: 3, ready: 3, want: "Ready"},          // healthy steady-state
		{desired: 3, ready: 0, want: "Pending"},        // cold start
		{desired: 3, ready: 1, want: "Progressing"},    // scaling up
		{desired: 0, ready: 0, want: "Ready"},          // intentional scale-to-zero, quiesced
		{desired: 0, ready: 3, want: "Progressing"},    // scale-to-zero in flight
		{desired: 2, ready: 5, want: "Progressing"},    // scale-down in flight
	}
	for _, tc := range cases {
		if got := derivePhase(tc.desired, tc.ready); got != tc.want {
			t.Errorf("derivePhase(desired=%d, ready=%d) = %q, want %q", tc.desired, tc.ready, got, tc.want)
		}
	}
}

func TestReconcile_ScaledToZero_IsReadyAndPropagatesZeroToDeployment(t *testing.T) {
	// Explicit scale-to-zero: Replicas is a non-nil pointer to 0. The
	// reconciler must honor that (not promote to 1) and the Deployment
	// must be applied with Replicas=0 so the cluster actually shuts the
	// pods down.
	fc := &fakeClient{
		svc: &v1alpha1.NIMService{
			Metadata: v1alpha1.ObjectMeta{Name: "idle", Namespace: "nim", Generation: 3},
			Spec:     v1alpha1.NIMServiceSpec{Image: "x", Replicas: int32Ptr(0)},
		},
		deployment: &Deployment{ObservedReadyReplicas: 0},
	}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "idle"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if len(fc.createOrUpdate) != 1 {
		t.Fatalf("expected one apply call, got %d", len(fc.createOrUpdate))
	}
	if got := fc.createOrUpdate[0].Replicas; got != 0 {
		t.Errorf("deployment replicas: want 0 (honor scale-to-zero), got %d", got)
	}
	if fc.svc.Status.Phase != "Ready" {
		t.Errorf("phase: want Ready (intentional scale-to-zero is healthy), got %s", fc.svc.Status.Phase)
	}
}

func TestReconcile_OmittedReplicas_DefaultsToOne(t *testing.T) {
	// Omitted Replicas (nil pointer) should still default to 1 — the
	// historical behavior. Companion to the scale-to-zero test so both
	// branches of the pointer-semantics change are locked down.
	fc := &fakeClient{
		svc:        newSvc(v1alpha1.NIMServiceSpec{Image: "x"}), // Replicas nil
		deployment: &Deployment{ObservedReadyReplicas: 1},
	}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "x"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := fc.createOrUpdate[0].Replicas; got != 1 {
		t.Errorf("omitted replicas should default to 1, got %d", got)
	}
}

func TestReconcile_InvalidSpec_ErrorAndDegraded(t *testing.T) {
	fc := &fakeClient{
		svc: newSvc(v1alpha1.NIMServiceSpec{Image: ""}), // missing image
	}
	err := NewReconciler(fc).Reconcile(context.Background(), "nim", "broken")
	if err == nil {
		t.Fatal("expected reconcile to fail on invalid spec")
	}
	if fc.svc.Status.Phase != "Degraded" {
		t.Errorf("phase: want Degraded, got %s", fc.svc.Status.Phase)
	}
	if !hasCondition(fc.svc.Status.Conditions, "SpecValid", "False") {
		t.Error("missing SpecValid=False condition")
	}
	if len(fc.createOrUpdate) != 0 {
		t.Error("invalid spec must not produce a Deployment apply")
	}
}

func TestReconcile_GetNIMServiceError_IsRequeueable(t *testing.T) {
	fc := &fakeClient{getSvcErr: errors.New("api unreachable")}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "x"); err == nil {
		t.Error("expected error when GetNIMService fails (controller-runtime requeues)")
	}
}

func TestReconcile_DeletedNIMService_NoOp(t *testing.T) {
	fc := &fakeClient{svc: nil}
	if err := NewReconciler(fc).Reconcile(context.Background(), "nim", "gone"); err != nil {
		t.Fatalf("deleted resource should not error: %v", err)
	}
	if len(fc.createOrUpdate) != 0 {
		t.Error("deleted resource must not trigger Deployment writes")
	}
}

func TestBuildDeployment_LabelsAndEnv(t *testing.T) {
	svc := newSvc(v1alpha1.NIMServiceSpec{
		Image:         "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:      int32Ptr(2),
		Model:         "llama3-8b",
		NGCSecretName: "my-key",
		GPURequest:    4,
		Port:          9000,
	})
	// Normally ApplyDefaults is called inside Reconcile; BuildDeployment
	// is a pure mapping and caller's responsibility to default first.
	svc.Spec.ApplyDefaults()

	d := BuildDeployment(svc)
	if d.Labels["nim.modelgate.dev/model"] != "llama3-8b" {
		t.Errorf("model label: %q", d.Labels["nim.modelgate.dev/model"])
	}
	if d.GPURequest != 4 {
		t.Errorf("GPU request: want 4, got %d", d.GPURequest)
	}
	if d.Port != 9000 {
		t.Errorf("port: want 9000, got %d", d.Port)
	}
	if d.Env["NGC_API_KEY"] != "secret:my-key" {
		t.Errorf("env: %+v", d.Env)
	}
}

func TestBuildDeployment_PropagatesOwnerUID(t *testing.T) {
	svc := newSvc(v1alpha1.NIMServiceSpec{Image: "img:1"})
	svc.Metadata.UID = "abc-123"
	svc.Spec.ApplyDefaults()

	d := BuildDeployment(svc)
	if d.OwnerUID != "abc-123" {
		t.Errorf("OwnerUID: want abc-123, got %q", d.OwnerUID)
	}
}

func hasCondition(cs []v1alpha1.Condition, typ, status string) bool {
	for _, c := range cs {
		if c.Type == typ && c.Status == status {
			return true
		}
	}
	return false
}
