package v1alpha1

import "fmt"

// NIMService is the Kubernetes-style resource that declares a NVIDIA NIM
// deployment to reconcile. The controller in internal/controller owns
// materializing this into an actual Deployment + Service and reporting
// status back here.
//
// This package uses plain structs rather than pulling in
// k8s.io/apimachinery so the modelgate binary stays small when deployed
// outside of a cluster. A follow-up PR adds the controller-runtime
// wiring behind a build tag; the Spec/Status shapes here are
// deliberately identical to what that CRD will declare.
type NIMService struct {
	Kind       string           `json:"kind,omitempty"`
	APIVersion string           `json:"apiVersion,omitempty"`
	Metadata   ObjectMeta       `json:"metadata"`
	Spec       NIMServiceSpec   `json:"spec"`
	Status     NIMServiceStatus `json:"status,omitempty"`
}

// ObjectMeta mirrors the subset of k8s.io/apimachinery/pkg/apis/meta/v1
// that the controller needs.
type ObjectMeta struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Generation int64             `json:"generation,omitempty"`

	// UID is the cluster-assigned identity of the underlying object.
	// The adapter stamps it onto the Deployment it creates as an
	// OwnerReference so Kubernetes garbage-collects the Deployment when
	// the NIMService is deleted. Empty for specs built outside a live
	// cluster (e.g. test fixtures) — the adapter skips owner-reference
	// stamping in that case rather than emit a reference with no UID.
	UID string `json:"uid,omitempty"`
}

// NIMServiceSpec declares the desired state of a NIM deployment.
type NIMServiceSpec struct {
	// Image is the NIM container image (e.g. nvcr.io/nim/meta/llama3-8b:1.0.0).
	Image string `json:"image"`

	// Replicas is the desired replica count. Pointer semantics so callers
	// can explicitly scale to zero — a value-type int32 cannot distinguish
	// "field omitted" from "explicit 0" and the defaulting logic would
	// then silently re-promote an intentional scale-down back to 1.
	// Defaults to 1 when nil.
	Replicas *int32 `json:"replicas,omitempty"`

	// Model is the model name served by this NIM. Informational — surfaced
	// in status + labels so operators can filter by model.
	Model string `json:"model,omitempty"`

	// NGCSecretName is the name of the Kubernetes Secret holding an
	// NGC_API_KEY key. The controller projects this into the pod as the
	// NGC_API_KEY env var required by every NIM image.
	NGCSecretName string `json:"ngcSecretName,omitempty"`

	// GPURequest is the number of GPUs requested via
	// `nvidia.com/gpu` resource quota. Defaults to 1 when unset.
	GPURequest int32 `json:"gpuRequest,omitempty"`

	// Port is the HTTP port the NIM pod listens on. Defaults to 8000.
	Port int32 `json:"port,omitempty"`

	// Resources tunes CPU and memory requests + limits. When nil, the
	// adapter falls back to its built-in defaults (CPU 500m + memory
	// 2Gi as REQUESTS ONLY, no CPU/memory LIMITS, GPU limit stays at
	// GPURequest). When set, empty fields keep those defaults; only
	// specified values override. This is the operator knob the Tuesday
	// hardening slice explicitly left as follow-up because a hardcoded
	// CPU/memory LIMIT would throttle or OOMKill some workloads.
	Resources *NIMServiceResources `json:"resources,omitempty"`

	// ReadOnlyRootFilesystem opts the rendered container into a
	// read-only root filesystem. Off by default because NIM images
	// write to caches inside the image and per-image testing is
	// required to know which paths need writable mounts (which is why
	// Tuesday's slice explicitly did NOT default this on). When true,
	// WritableMounts declares the paths that stay writable via
	// per-path emptyDir volumes.
	ReadOnlyRootFilesystem bool `json:"readOnlyRootFilesystem,omitempty"`

	// WritableMounts is the list of paths that stay writable when
	// ReadOnlyRootFilesystem is true. Each path becomes an emptyDir
	// volume mounted at that location.
	//
	// Default when ReadOnlyRootFilesystem=true and the list is empty:
	// ["/tmp"]. This default is a guess based on the general NIM shape
	// and HAS NOT BEEN VERIFIED against a specific image; NIM images
	// commonly write elsewhere too (/var/cache, /root/.cache, model
	// download directories). An operator who flips the switch and
	// discovers their image needs additional paths adds them to this
	// list in the NIMService CR rather than filing a bug against the
	// operator. Document your image's actual write set before relying
	// on the default.
	WritableMounts []string `json:"writableMounts,omitempty"`
}

// NIMServiceResources tunes container CPU + memory requests and limits.
// Mirrors the shape of corev1.ResourceRequirements at a plain-Go level
// so the reconciler stays k8s-free — the adapter parses these strings
// through resource.MustParse at render time.
type NIMServiceResources struct {
	// Requests are the guaranteed reservations the scheduler honours.
	Requests *NIMServiceResourceList `json:"requests,omitempty"`

	// Limits are the hard ceilings enforced by the kubelet. When nil,
	// the container is Burstable — it can grow past its Requests up
	// to the node's spare capacity. Set when the operator has verified
	// their workload's ceiling and wants OOMKill / throttle at that
	// bound rather than at node exhaustion.
	Limits *NIMServiceResourceList `json:"limits,omitempty"`
}

// NIMServiceResourceList is the CPU + memory pair inside Requests /
// Limits. Strings so the operator writes k8s-native quantities
// ("500m", "2Gi") that the adapter parses via resource.MustParse.
// Empty fields fall back to the adapter's built-in defaults for
// Requests; empty Limits fields mean "no ceiling on this dimension."
type NIMServiceResourceList struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// NIMServiceStatus reflects the observed state reconciled by the controller.
type NIMServiceStatus struct {
	// ObservedGeneration is the spec Generation most recently acted on.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ReadyReplicas is the number of pods currently passing the NIM
	// readiness probe (/v1/health/ready).
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Phase is a short summary useful in `kubectl get`:
	// Pending | Progressing | Ready | Degraded.
	Phase string `json:"phase,omitempty"`

	// Conditions records structured reasons for the current Phase.
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition is a trimmed metav1.Condition.
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"` // True | False | Unknown
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// Validate rejects obviously-broken specs up front so reconcile never has
// to handle malformed input.
func (s *NIMServiceSpec) Validate() error {
	if s.Image == "" {
		return fmt.Errorf("spec.image is required")
	}
	if s.Replicas != nil && *s.Replicas < 0 {
		return fmt.Errorf("spec.replicas must be >= 0, got %d", *s.Replicas)
	}
	if s.GPURequest < 0 {
		return fmt.Errorf("spec.gpuRequest must be >= 0, got %d", s.GPURequest)
	}
	if s.Port < 0 || s.Port > 65535 {
		return fmt.Errorf("spec.port must be 0..65535, got %d", s.Port)
	}
	return nil
}

// ApplyDefaults fills in the conventional defaults for omitted fields.
// Called by the reconciler before materializing the Deployment so tests
// and real deploys see the same canonical spec.
func (s *NIMServiceSpec) ApplyDefaults() {
	if s.Replicas == nil {
		one := int32(1)
		s.Replicas = &one
	}
	if s.GPURequest == 0 {
		s.GPURequest = 1
	}
	if s.Port == 0 {
		s.Port = 8000
	}
}

// DesiredReplicas returns the effective replica count after defaulting.
// Safe to call on a zero-value spec; returns 1.
func (s *NIMServiceSpec) DesiredReplicas() int32 {
	if s.Replicas == nil {
		return 1
	}
	return *s.Replicas
}
