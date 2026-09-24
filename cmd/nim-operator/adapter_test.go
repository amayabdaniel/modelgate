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

// TestRenderDeployment_EmptySpecPreservesTuesdayDefaults is the
// back-compat guard peer named as the one most likely to break silently
// when a future PR adds a spec field with a non-zero default. An
// existing NIMService CR that doesn't set Spec.Resources or
// Spec.ReadOnlyRootFilesystem MUST render exactly Tuesday's hardening
// output — same requests, same absence of limits, same absence of
// read-only-root, same absence of extra volumes/mounts. Any addition
// that changes this without an operator opt-in is a regression this
// test catches.
func TestRenderDeployment_EmptySpecPreservesTuesdayDefaults(t *testing.T) {
	d := &controller.Deployment{
		Name:       "llama3-8b",
		Namespace:  "nim",
		Image:      "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:   1,
		GPURequest: 1,
		Port:       8000,
		// Every override field left zero-valued.
	}
	got := renderDeployment(d)
	pod := got.Spec.Template.Spec
	c := pod.Containers[0]

	// CPU + memory requests EXACTLY 500m + 2Gi (Tuesday's numbers).
	if cpu := c.Resources.Requests[corev1.ResourceCPU]; cpu.String() != "500m" {
		t.Errorf("empty spec: CPU request must be 500m (Tuesday default), got %s", cpu.String())
	}
	if mem := c.Resources.Requests[corev1.ResourceMemory]; mem.String() != "2Gi" {
		t.Errorf("empty spec: memory request must be 2Gi (Tuesday default), got %s", mem.String())
	}
	// GPU limit + request from GPURequest.
	if gpu := c.Resources.Limits["nvidia.com/gpu"]; gpu.Value() != 1 {
		t.Errorf("empty spec: GPU limit must be 1, got %d", gpu.Value())
	}
	// NO CPU limit, NO memory limit (Burstable-QoS by design).
	if _, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		t.Errorf("empty spec: CPU LIMIT must be absent (Tuesday's Burstable-QoS choice), got %v", c.Resources.Limits[corev1.ResourceCPU])
	}
	if _, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
		t.Errorf("empty spec: memory LIMIT must be absent, got %v", c.Resources.Limits[corev1.ResourceMemory])
	}
	// NO readOnlyRootFilesystem — Tuesday opted OUT because per-image
	// write-path testing was needed.
	if c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
		t.Errorf("empty spec: ReadOnlyRootFilesystem must remain unset (opt-in only)")
	}
	// NO extra volumes / volumeMounts (there were none in Tuesday's
	// output and there should still be none until an operator opts in).
	if len(pod.Volumes) != 0 {
		t.Errorf("empty spec: pod.Volumes must be empty, got %d entries: %+v", len(pod.Volumes), pod.Volumes)
	}
	if len(c.VolumeMounts) != 0 {
		t.Errorf("empty spec: container.VolumeMounts must be empty, got %d entries: %+v", len(c.VolumeMounts), c.VolumeMounts)
	}
}

// TestRenderDeployment_ResourceOverridesApply asserts the adapter
// honours Spec.Resources.Requests and .Limits per-field, and that
// setting one doesn't disturb the other's default.
func TestRenderDeployment_ResourceOverridesApply(t *testing.T) {
	d := &controller.Deployment{
		Name:          "llama3-8b",
		Namespace:     "nim",
		Image:         "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:      1,
		GPURequest:    1,
		Port:          8000,
		CPURequest:    "2",
		MemoryRequest: "8Gi",
		CPULimit:      "4",
		MemoryLimit:   "16Gi",
	}
	got := renderDeployment(d)
	c := got.Spec.Template.Spec.Containers[0]

	if cpu := c.Resources.Requests[corev1.ResourceCPU]; cpu.String() != "2" {
		t.Errorf("CPU request override should be 2, got %s", cpu.String())
	}
	if mem := c.Resources.Requests[corev1.ResourceMemory]; mem.String() != "8Gi" {
		t.Errorf("memory request override should be 8Gi, got %s", mem.String())
	}
	if cpu := c.Resources.Limits[corev1.ResourceCPU]; cpu.String() != "4" {
		t.Errorf("CPU limit override should be 4, got %s", cpu.String())
	}
	if mem := c.Resources.Limits[corev1.ResourceMemory]; mem.String() != "16Gi" {
		t.Errorf("memory limit override should be 16Gi, got %s", mem.String())
	}
}

// TestRenderDeployment_ReadOnlyRootFilesystem_OptInWithDefaultMount
// asserts the ROrootfs opt-in + default-mount behaviour peer's key
// correction landed: when ReadOnlyRootFilesystem is on and
// WritableMounts is empty, the adapter defaults to ["/tmp"] — a
// documented guess based on the general NIM shape, overrideable per
// NIMService when the operator has verified their image needs
// different paths.
func TestRenderDeployment_ReadOnlyRootFilesystem_OptInWithDefaultMount(t *testing.T) {
	d := &controller.Deployment{
		Name:                   "llama3-8b",
		Namespace:              "nim",
		Image:                  "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:               1,
		GPURequest:             1,
		Port:                   8000,
		ReadOnlyRootFilesystem: true,
		// WritableMounts left empty → default ["/tmp"] applied.
	}
	got := renderDeployment(d)
	pod := got.Spec.Template.Spec
	c := pod.Containers[0]

	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("ReadOnlyRootFilesystem must be set on container SecurityContext, got %+v", c.SecurityContext)
	}
	if len(pod.Volumes) != 1 {
		t.Fatalf("empty WritableMounts + ROrootfs=true → exactly one default emptyDir volume, got %d: %+v", len(pod.Volumes), pod.Volumes)
	}
	if pod.Volumes[0].EmptyDir == nil {
		t.Errorf("default writable volume must be emptyDir, got %+v", pod.Volumes[0].VolumeSource)
	}
	if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != "/tmp" {
		t.Errorf("empty WritableMounts + ROrootfs=true → default mount at /tmp, got %+v", c.VolumeMounts)
	}
}

// TestRenderDeployment_ReadOnlyRootFilesystem_OptInWithCustomMounts
// asserts operator-provided WritableMounts override the /tmp default.
// Two distinct paths so ordering + count are both exercised.
func TestRenderDeployment_ReadOnlyRootFilesystem_OptInWithCustomMounts(t *testing.T) {
	d := &controller.Deployment{
		Name:                   "llama3-8b",
		Namespace:              "nim",
		Image:                  "nvcr.io/nim/meta/llama3-8b:1.0.0",
		Replicas:               1,
		GPURequest:             1,
		Port:                   8000,
		ReadOnlyRootFilesystem: true,
		WritableMounts:         []string{"/tmp", "/var/cache/nim"},
	}
	got := renderDeployment(d)
	pod := got.Spec.Template.Spec
	c := pod.Containers[0]

	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatalf("ReadOnlyRootFilesystem must be set, got %+v", c.SecurityContext)
	}
	if len(pod.Volumes) != 2 {
		t.Fatalf("expected 2 emptyDir volumes for 2 WritableMounts, got %d: %+v", len(pod.Volumes), pod.Volumes)
	}
	if len(c.VolumeMounts) != 2 {
		t.Fatalf("expected 2 VolumeMounts, got %d: %+v", len(c.VolumeMounts), c.VolumeMounts)
	}
	if c.VolumeMounts[0].MountPath != "/tmp" || c.VolumeMounts[1].MountPath != "/var/cache/nim" {
		t.Errorf("VolumeMount paths must match WritableMounts order, got %+v", c.VolumeMounts)
	}
	// Volume names must be unique per index so a k8s server doesn't
	// reject the pod for duplicate volume names.
	if pod.Volumes[0].Name == pod.Volumes[1].Name {
		t.Errorf("volume names must be unique, got %q and %q", pod.Volumes[0].Name, pod.Volumes[1].Name)
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
