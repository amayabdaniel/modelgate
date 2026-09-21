//go:build k8s

package main

import (
	"testing"

	"github.com/amayabdaniel/modelgate/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

func TestRenderDeploymentBasics(t *testing.T) {
	d := &controller.Deployment{
		Name:       "llama3-8b",
		Namespace:  "nim",
		Labels:     map[string]string{"team": "ml"},
		Image:      "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:   3,
		GPURequest: 2,
		Port:       8000,
		Env:        map[string]string{"NGC_API_KEY": "secret:ngc-creds"},
	}

	got := renderDeployment(d)

	if got.Name != d.Name || got.Namespace != d.Namespace {
		t.Fatalf("name/namespace mismatch: got %s/%s", got.Namespace, got.Name)
	}
	if got.Labels["team"] != "ml" {
		t.Fatalf("expected base label preserved, got %v", got.Labels)
	}
	if got.Spec.Replicas == nil || *got.Spec.Replicas != 3 {
		t.Fatalf("expected replicas 3, got %v", got.Spec.Replicas)
	}
	if len(got.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected exactly one container, got %d", len(got.Spec.Template.Spec.Containers))
	}

	c := got.Spec.Template.Spec.Containers[0]
	if c.Image != d.Image {
		t.Fatalf("expected image %s, got %s", d.Image, c.Image)
	}
	if len(c.Ports) != 1 || c.Ports[0].ContainerPort != 8000 {
		t.Fatalf("expected container port 8000, got %+v", c.Ports)
	}
	if c.ReadinessProbe == nil || c.ReadinessProbe.HTTPGet == nil || c.ReadinessProbe.HTTPGet.Path != "/v1/health/ready" {
		t.Fatalf("expected readiness probe on /v1/health/ready, got %+v", c.ReadinessProbe)
	}

	gpuLimit := c.Resources.Limits["nvidia.com/gpu"]
	if gpuLimit.Value() != 2 {
		t.Fatalf("expected GPU limit 2, got %v", gpuLimit.Value())
	}
	gpuReq := c.Resources.Requests["nvidia.com/gpu"]
	if gpuReq.Value() != 2 {
		t.Fatalf("expected GPU request 2, got %v", gpuReq.Value())
	}

	// Selector must key off the stable app-name label, independent of
	// caller-supplied labels, since Selector is immutable after Create.
	if got.Spec.Selector.MatchLabels["app.kubernetes.io/name"] != d.Name {
		t.Fatalf("expected selector app.kubernetes.io/name=%s, got %v", d.Name, got.Spec.Selector.MatchLabels)
	}
	if got.Spec.Template.Labels["app.kubernetes.io/name"] != d.Name || got.Spec.Template.Labels["team"] != "ml" {
		t.Fatalf("expected template labels to merge base+app name, got %v", got.Spec.Template.Labels)
	}
}

// TestRenderDeploymentHardeningDefaults locks in the first-slice
// pod/container hardening defaults renderDeployment applies. This is
// a governance product; a pod spec that ships with no securityContext
// or resource requests is an availability problem in its own right,
// and the CRIT-severity finding peer flagged. The defaults asserted
// here are the ones safe to apply without a NIMService.Spec extension.
// Explicit-not-included items (readOnlyRootFilesystem, runAsUser,
// CPU/memory limits, per-NIMService NetworkPolicy) are recorded in the
// renderDeployment comment as follow-up scope.
//
// This test would fail on the pre-slice adapter and pins the shape
// against silent regressions of any single knob.
func TestRenderDeploymentHardeningDefaults(t *testing.T) {
	d := &controller.Deployment{
		Name:       "llama3-8b",
		Namespace:  "nim",
		Image:      "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:   1,
		GPURequest: 1,
		Port:       8000,
	}

	got := renderDeployment(d)
	pod := got.Spec.Template.Spec

	// Pod: automountServiceAccountToken must be false — NIM does not
	// call the K8s API, and mounting the SA token is an exfiltration
	// surface for a jailbroken workload.
	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Errorf("PodSpec.AutomountServiceAccountToken must be explicitly false, got %v", pod.AutomountServiceAccountToken)
	}
	// Pod: runAsNonRoot must be true — kubelet rejects a root-USER
	// image, surfacing misconfigured images loudly.
	if pod.SecurityContext == nil || pod.SecurityContext.RunAsNonRoot == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Errorf("PodSecurityContext.RunAsNonRoot must be true, got %+v", pod.SecurityContext)
	}
	// Pod: seccompProfile RuntimeDefault — PodSecurityStandards
	// restricted profile admission requires this.
	if pod.SecurityContext == nil || pod.SecurityContext.SeccompProfile == nil || pod.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Errorf("PodSecurityContext.SeccompProfile.Type must be RuntimeDefault, got %+v", pod.SecurityContext)
	}

	if len(pod.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(pod.Containers))
	}
	c := pod.Containers[0]

	// Container: allowPrivilegeEscalation must be false — no setuid
	// path to root.
	if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Errorf("Container.SecurityContext.AllowPrivilegeEscalation must be explicitly false, got %+v", c.SecurityContext)
	}
	// Container: capabilities.drop must include ALL — NIM needs no
	// Linux capabilities.
	if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
		t.Fatalf("Container.SecurityContext.Capabilities must be set, got %+v", c.SecurityContext)
	}
	dropped := c.SecurityContext.Capabilities.Drop
	foundAll := false
	for _, cap := range dropped {
		if cap == "ALL" {
			foundAll = true
		}
	}
	if !foundAll {
		t.Errorf("Container.SecurityContext.Capabilities.Drop must contain ALL, got %v", dropped)
	}

	// Resources: CPU + memory REQUESTS present (defensive scheduling
	// headroom). LIMITS deliberately absent for CPU/memory pending a
	// NIMService.Spec knob — see renderDeployment comment. Test asserts
	// requests to prevent them being accidentally dropped; does not
	// assert the absence of limits, since a future PR adding LIMITS
	// behind a Spec extension is a valid change, not a regression.
	cpuReq := c.Resources.Requests[corev1.ResourceCPU]
	if cpuReq.IsZero() {
		t.Errorf("Container.Resources.Requests[cpu] must be set (defensive scheduling headroom), got zero")
	}
	memReq := c.Resources.Requests[corev1.ResourceMemory]
	if memReq.IsZero() {
		t.Errorf("Container.Resources.Requests[memory] must be set (defensive scheduling headroom), got zero")
	}
}

func TestRenderDeploymentOwnerReference(t *testing.T) {
	d := &controller.Deployment{
		Name:      "llama3-8b",
		Namespace: "nim",
		OwnerUID:  "abc-123",
	}

	got := renderDeployment(d)
	refs := got.OwnerReferences
	if len(refs) != 1 {
		t.Fatalf("expected exactly one owner reference, got %+v", refs)
	}
	ref := refs[0]
	if ref.Kind != "NIMService" {
		t.Errorf("expected owner Kind NIMService, got %q", ref.Kind)
	}
	if ref.APIVersion != "modelgate.dev/v1alpha1" {
		t.Errorf("expected owner APIVersion modelgate.dev/v1alpha1, got %q", ref.APIVersion)
	}
	if ref.Name != d.Name {
		t.Errorf("expected owner Name %s, got %s", d.Name, ref.Name)
	}
	if string(ref.UID) != d.OwnerUID {
		t.Errorf("expected owner UID %s, got %s", d.OwnerUID, ref.UID)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Error("expected Controller=true so GC treats NIMService as the controlling owner")
	}
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Error("expected BlockOwnerDeletion=true")
	}
}

func TestRenderDeploymentNoOwnerReferenceWithoutUID(t *testing.T) {
	d := &controller.Deployment{Name: "bare", Namespace: "default"}

	got := renderDeployment(d)
	if got.OwnerReferences != nil {
		t.Fatalf("expected no owner references when OwnerUID is empty, got %+v", got.OwnerReferences)
	}
}

func TestRenderDeploymentEnvSecretRef(t *testing.T) {
	d := &controller.Deployment{
		Name: "svc",
		Env: map[string]string{
			"NGC_API_KEY": "secret:ngc-creds",
			"MODEL_NAME":  "llama3-8b",
		},
	}

	got := renderDeployment(d)
	envs := got.Spec.Template.Spec.Containers[0].Env

	byName := make(map[string]corev1.EnvVar, len(envs))
	for _, e := range envs {
		byName[e.Name] = e
	}

	secretEnv := byName["NGC_API_KEY"]
	if secretEnv.ValueFrom == nil || secretEnv.ValueFrom.SecretKeyRef == nil {
		t.Fatalf("expected NGC_API_KEY to be a SecretKeyRef, got %+v", secretEnv)
	}
	if secretEnv.ValueFrom.SecretKeyRef.Name != "ngc-creds" {
		t.Fatalf("expected secret name ngc-creds, got %s", secretEnv.ValueFrom.SecretKeyRef.Name)
	}
	if secretEnv.ValueFrom.SecretKeyRef.Key != "NGC_API_KEY" {
		t.Fatalf("expected secret key NGC_API_KEY, got %s", secretEnv.ValueFrom.SecretKeyRef.Key)
	}
	if secretEnv.Value != "" {
		t.Fatalf("expected empty literal Value on secret ref, got %q", secretEnv.Value)
	}

	plainEnv := byName["MODEL_NAME"]
	if plainEnv.ValueFrom != nil {
		t.Fatalf("expected MODEL_NAME to be a literal value, got ValueFrom %+v", plainEnv.ValueFrom)
	}
	if plainEnv.Value != "llama3-8b" {
		t.Fatalf("expected literal value llama3-8b, got %s", plainEnv.Value)
	}
}

func TestRenderDeploymentEnvSecretPrefixWithoutName(t *testing.T) {
	// "secret:" alone (no name after the prefix) does not satisfy the
	// `len(v) > len("secret:")` check, so it is treated as a literal
	// value rather than an empty-named SecretKeyRef.
	d := &controller.Deployment{
		Name: "svc",
		Env:  map[string]string{"WEIRD": "secret:"},
	}

	got := renderDeployment(d)
	env := got.Spec.Template.Spec.Containers[0].Env[0]
	if env.ValueFrom != nil {
		t.Fatalf("expected bare 'secret:' to fall back to literal value, got ValueFrom %+v", env.ValueFrom)
	}
	if env.Value != "secret:" {
		t.Fatalf("expected literal value 'secret:', got %q", env.Value)
	}
}

func TestRenderDeploymentNilLabelsAndEnv(t *testing.T) {
	d := &controller.Deployment{Name: "bare", Namespace: "default"}

	got := renderDeployment(d)
	if got.Labels == nil {
		t.Fatal("expected non-nil Labels map even when input Labels is nil")
	}
	if len(got.Spec.Template.Spec.Containers[0].Env) != 0 {
		t.Fatalf("expected no env vars, got %+v", got.Spec.Template.Spec.Containers[0].Env)
	}
}

func TestMergeLabels(t *testing.T) {
	cases := []struct {
		name  string
		base  map[string]string
		extra map[string]string
		want  map[string]string
	}{
		{"both nil", nil, nil, map[string]string{}},
		{"nil base", nil, map[string]string{"a": "1"}, map[string]string{"a": "1"}},
		{"nil extra", map[string]string{"a": "1"}, nil, map[string]string{"a": "1"}},
		{"extra wins on conflict", map[string]string{"a": "1"}, map[string]string{"a": "2"}, map[string]string{"a": "2"}},
		{"disjoint merge", map[string]string{"a": "1"}, map[string]string{"b": "2"}, map[string]string{"a": "1", "b": "2"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeLabels(tc.base, tc.extra)
			if len(got) != len(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("expected %v, got %v", tc.want, got)
				}
			}
		})
	}
}

func TestFirstContainerImageAndPort(t *testing.T) {
	empty := &appsv1.Deployment{}
	if img := firstContainerImage(empty); img != "" {
		t.Fatalf("expected empty image for containerless deployment, got %q", img)
	}
	if p := firstContainerPort(empty); p != 0 {
		t.Fatalf("expected port 0 for containerless deployment, got %d", p)
	}

	noPorts := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "img:1"}}},
	}}}
	if img := firstContainerImage(noPorts); img != "img:1" {
		t.Fatalf("expected image img:1, got %q", img)
	}
	if p := firstContainerPort(noPorts); p != 0 {
		t.Fatalf("expected port 0 when container has no ports, got %d", p)
	}

	full := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Image: "img:2",
			Ports: []corev1.ContainerPort{{ContainerPort: 9000}},
		}}},
	}}}
	if img := firstContainerImage(full); img != "img:2" {
		t.Fatalf("expected image img:2, got %q", img)
	}
	if p := firstContainerPort(full); p != 9000 {
		t.Fatalf("expected port 9000, got %d", p)
	}
}

func TestSpecReplicas(t *testing.T) {
	if r := specReplicas(&appsv1.Deployment{}); r != 0 {
		t.Fatalf("expected 0 replicas when Spec.Replicas is nil, got %d", r)
	}

	want := int32(5)
	d := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: &want}}
	if r := specReplicas(d); r != 5 {
		t.Fatalf("expected 5 replicas, got %d", r)
	}
}
