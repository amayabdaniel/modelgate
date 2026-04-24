// Package controller implements a minimal reconciler for NIMService
// resources. It is deliberately free of k8s.io dependencies: the
// Deployment shape is expressed through a small `Client` interface so the
// full business logic can be exercised under `go test` without kind or a
// live cluster.
//
// A follow-up PR adds a thin controller-runtime adapter that translates
// between this Client interface and real k8s.io/apimachinery types. The
// reconcile algorithm here does not change in that PR.
package controller

import (
	"context"
	"fmt"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
)

// Deployment is the subset of apps/v1 Deployment fields the controller
// owns. Anything the reconciler doesn't set (e.g. strategy, selectors
// beyond name) is the cluster's concern.
type Deployment struct {
	Name       string
	Namespace  string
	Labels     map[string]string
	Image      string
	Replicas   int32
	GPURequest int32
	Port       int32

	// Env values projected into the pod. Values prefixed with `secret:`
	// are sourced from a Kubernetes Secret named after the prefix is
	// stripped, with the same key as the env var. The real adapter
	// translates these into `EnvVarSource.SecretKeyRef`.
	Env map[string]string

	// ObservedReadyReplicas is filled in by the Client on GetDeployment.
	// Reconcile() leaves it untouched when planning desired state.
	ObservedReadyReplicas int32
}

// Client is the narrow surface the reconciler needs from Kubernetes.
// The real implementation wraps controller-runtime; tests use a fake.
type Client interface {
	GetNIMService(ctx context.Context, namespace, name string) (*v1alpha1.NIMService, error)
	UpdateNIMServiceStatus(ctx context.Context, svc *v1alpha1.NIMService) error

	GetDeployment(ctx context.Context, namespace, name string) (*Deployment, error)
	CreateOrUpdateDeployment(ctx context.Context, d *Deployment) error
}

// Reconciler reconciles NIMService resources.
type Reconciler struct {
	client Client
}

func NewReconciler(c Client) *Reconciler { return &Reconciler{client: c} }

// Reconcile is the one-shot reconcile entry point. It:
//
//  1. Fetches the NIMService.
//  2. Validates + defaults its spec.
//  3. Computes the desired Deployment and asks the client to apply it.
//  4. Reads the live Deployment to update NIMServiceStatus.
//
// Callers (controller-runtime or a test harness) invoke Reconcile from
// whatever event stream drives them. The return error signals that the
// caller should requeue.
func (r *Reconciler) Reconcile(ctx context.Context, namespace, name string) error {
	svc, err := r.client.GetNIMService(ctx, namespace, name)
	if err != nil {
		return fmt.Errorf("get NIMService %s/%s: %w", namespace, name, err)
	}
	if svc == nil {
		// Deleted — nothing for the reconciler to do. Real adapter will
		// rely on owner references to garbage-collect the Deployment.
		return nil
	}

	if err := svc.Spec.Validate(); err != nil {
		svc.Status.Phase = "Degraded"
		svc.Status.Conditions = setCondition(svc.Status.Conditions, v1alpha1.Condition{
			Type: "SpecValid", Status: "False", Reason: "Invalid", Message: err.Error(),
		})
		// Best-effort status update — we ignore the error here because
		// the primary error is the spec itself.
		_ = r.client.UpdateNIMServiceStatus(ctx, svc)
		return fmt.Errorf("invalid NIMService spec: %w", err)
	}
	svc.Spec.ApplyDefaults()

	desired := BuildDeployment(svc)
	if err := r.client.CreateOrUpdateDeployment(ctx, desired); err != nil {
		return fmt.Errorf("reconcile deployment: %w", err)
	}

	// Re-read to capture live replica counts reported by the cluster.
	live, err := r.client.GetDeployment(ctx, desired.Namespace, desired.Name)
	if err != nil {
		return fmt.Errorf("get deployment after apply: %w", err)
	}

	svc.Status.ObservedGeneration = svc.Metadata.Generation
	svc.Status.ReadyReplicas = live.ObservedReadyReplicas
	svc.Status.Phase = derivePhase(svc.Spec.Replicas, live.ObservedReadyReplicas)
	svc.Status.Conditions = setCondition(svc.Status.Conditions, v1alpha1.Condition{
		Type: "SpecValid", Status: "True", Reason: "Applied",
	})
	if svc.Spec.NGCSecretName == "" {
		svc.Status.Conditions = setCondition(svc.Status.Conditions, v1alpha1.Condition{
			Type: "NGCKeyPresent", Status: "False",
			Reason:  "Missing",
			Message: "spec.ngcSecretName unset — NIM container will 401 on every request",
		})
	} else {
		svc.Status.Conditions = setCondition(svc.Status.Conditions, v1alpha1.Condition{
			Type: "NGCKeyPresent", Status: "True", Reason: "Projected",
		})
	}

	return r.client.UpdateNIMServiceStatus(ctx, svc)
}

// BuildDeployment maps a defaulted NIMServiceSpec to the Deployment shape
// the adapter will apply. Exposed for testing; a pure function so callers
// can verify the result without running Reconcile end-to-end.
func BuildDeployment(svc *v1alpha1.NIMService) *Deployment {
	labels := map[string]string{
		"app.kubernetes.io/name":       svc.Metadata.Name,
		"app.kubernetes.io/managed-by": "modelgate",
		"nim.modelgate.dev/model":      svc.Spec.Model,
	}
	env := map[string]string{}
	if svc.Spec.NGCSecretName != "" {
		env["NGC_API_KEY"] = "secret:" + svc.Spec.NGCSecretName
	}

	return &Deployment{
		Name:       svc.Metadata.Name,
		Namespace:  svc.Metadata.Namespace,
		Labels:     labels,
		Image:      svc.Spec.Image,
		Replicas:   svc.Spec.Replicas,
		GPURequest: svc.Spec.GPURequest,
		Port:       svc.Spec.Port,
		Env:        env,
	}
}

// derivePhase summarizes the reconcile state for `kubectl get`.
func derivePhase(desired, ready int32) string {
	switch {
	case desired == 0:
		return "Ready" // intentionally scaled to zero
	case ready == 0:
		return "Pending"
	case ready < desired:
		return "Progressing"
	case ready == desired:
		return "Ready"
	default:
		return "Ready"
	}
}

// setCondition replaces a condition of the same Type if present, else
// appends. Preserves stable ordering, which makes status diffs easier to
// read in kubectl describe output.
func setCondition(in []v1alpha1.Condition, c v1alpha1.Condition) []v1alpha1.Condition {
	for i, existing := range in {
		if existing.Type == c.Type {
			in[i] = c
			return in
		}
	}
	return append(in, c)
}
