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
	Kind       string            `json:"kind,omitempty"`
	APIVersion string            `json:"apiVersion,omitempty"`
	Metadata   ObjectMeta        `json:"metadata"`
	Spec       NIMServiceSpec    `json:"spec"`
	Status     NIMServiceStatus  `json:"status,omitempty"`
}

// ObjectMeta mirrors the subset of k8s.io/apimachinery/pkg/apis/meta/v1
// that the controller needs.
type ObjectMeta struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Generation int64             `json:"generation,omitempty"`
}

// NIMServiceSpec declares the desired state of a NIM deployment.
type NIMServiceSpec struct {
	// Image is the NIM container image (e.g. nvcr.io/nim/meta/llama3-8b:1.0.0).
	Image string `json:"image"`

	// Replicas is the desired replica count. Defaults to 1 when unset.
	Replicas int32 `json:"replicas,omitempty"`

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
	if s.Replicas < 0 {
		return fmt.Errorf("spec.replicas must be >= 0, got %d", s.Replicas)
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
	if s.Replicas == 0 {
		s.Replicas = 1
	}
	if s.GPURequest == 0 {
		s.GPURequest = 1
	}
	if s.Port == 0 {
		s.Port = 8000
	}
}
