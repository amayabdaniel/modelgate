//go:build k8s

// adapter.go implements internal/controller.Client using
// controller-runtime's client.Client. This is the thin glue layer that
// converts between metav1-flavored k8s objects and the plain-Go types
// the pure reconciler works with.
//
// Every method translates its arguments, delegates to the k8s client,
// and translates the result back. There is no reconciliation logic
// here — that's the whole point of the split.
package main

import (
	"context"
	"fmt"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// kubeClient wraps a controller-runtime client and satisfies the
// internal/controller.Client interface the pure-Go reconciler expects.
type kubeClient struct {
	c crclient.Client
}

func newKubeClient(c crclient.Client) *kubeClient { return &kubeClient{c: c} }

var _ controller.Client = (*kubeClient)(nil)

// GetNIMService reads the CR and returns the plain-Go representation.
// A NotFound error becomes (nil, nil) — the reconciler treats that as
// "resource deleted, no-op."
func (k *kubeClient) GetNIMService(ctx context.Context, namespace, name string) (*v1alpha1.NIMService, error) {
	var kn v1alpha1.KubeNIMService
	err := k.c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &kn)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get NIMService %s/%s: %w", namespace, name, err)
	}
	return v1alpha1.FromKubeNIMService(&kn), nil
}

// UpdateNIMServiceStatus writes the reconciler's status decisions back
// to the cluster. Uses the subresource writer so we don't accidentally
// stomp Spec on the read-modify-write.
func (k *kubeClient) UpdateNIMServiceStatus(ctx context.Context, svc *v1alpha1.NIMService) error {
	// Re-fetch to get the current ResourceVersion — required for
	// optimistic-concurrency writes. If someone else mutated the CR
	// between our Get and this call, the write will conflict and the
	// controller-runtime queue will retry.
	var kn v1alpha1.KubeNIMService
	if err := k.c.Get(ctx, types.NamespacedName{Namespace: svc.Metadata.Namespace, Name: svc.Metadata.Name}, &kn); err != nil {
		return fmt.Errorf("re-get for status update: %w", err)
	}
	kn.Status = svc.Status
	if err := k.c.Status().Update(ctx, &kn); err != nil {
		return fmt.Errorf("update NIMService status: %w", err)
	}
	return nil
}

// GetDeployment returns the current apps/v1 Deployment in the plain
// shape the reconciler compares against. Missing Deployment is not an
// error — the reconciler treats zero ObservedReadyReplicas as the
// signal that the pods aren't up yet.
func (k *kubeClient) GetDeployment(ctx context.Context, namespace, name string) (*controller.Deployment, error) {
	var d appsv1.Deployment
	err := k.c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &d)
	if apierrors.IsNotFound(err) {
		return &controller.Deployment{Name: name, Namespace: namespace}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get Deployment %s/%s: %w", namespace, name, err)
	}
	return &controller.Deployment{
		Name:                  d.Name,
		Namespace:             d.Namespace,
		Labels:                d.Labels,
		Image:                 firstContainerImage(&d),
		Replicas:              specReplicas(&d),
		Port:                  firstContainerPort(&d),
		ObservedReadyReplicas: d.Status.ReadyReplicas,
	}, nil
}

// CreateOrUpdateDeployment materializes the reconciler's desired state
// as a real apps/v1 Deployment. If the object exists we patch spec-
// relevant fields (image, replicas, env, resources); otherwise we
// create it fresh.
func (k *kubeClient) CreateOrUpdateDeployment(ctx context.Context, d *controller.Deployment) error {
	desired := renderDeployment(d)
	var existing appsv1.Deployment
	err := k.c.Get(ctx, types.NamespacedName{Namespace: d.Namespace, Name: d.Name}, &existing)
	if apierrors.IsNotFound(err) {
		return k.c.Create(ctx, desired)
	}
	if err != nil {
		return fmt.Errorf("pre-update get: %w", err)
	}
	// Patch a minimal set — Labels, container Spec, replica count.
	existing.Labels = desired.Labels
	existing.Spec.Replicas = desired.Spec.Replicas
	existing.Spec.Template = desired.Spec.Template
	// Selector is immutable after Create; preserve whatever exists.
	return k.c.Update(ctx, &existing)
}

// renderDeployment turns the reconciler's opinion into a full apps/v1
// Deployment object. Kept out of the reconciler so the pure-Go tests
// don't need to know about k8s field shapes.
func renderDeployment(d *controller.Deployment) *appsv1.Deployment {
	labels := d.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	envVars := make([]corev1.EnvVar, 0, len(d.Env))
	for k, v := range d.Env {
		env := corev1.EnvVar{Name: k}
		// "secret:<name>" convention from the reconciler → SecretKeyRef.
		if len(v) > len("secret:") && v[:len("secret:")] == "secret:" {
			secretName := v[len("secret:"):]
			env.ValueFrom = &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
					Key:                  k,
				},
			}
		} else {
			env.Value = v
		}
		envVars = append(envVars, env)
	}

	resources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			"nvidia.com/gpu": *resource.NewQuantity(int64(d.GPURequest), resource.DecimalSI),
		},
		Requests: corev1.ResourceList{
			"nvidia.com/gpu": *resource.NewQuantity(int64(d.GPURequest), resource.DecimalSI),
		},
	}

	replicas := d.Replicas
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      d.Name,
			Namespace: d.Namespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app.kubernetes.io/name": d.Name},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: mergeLabels(labels, map[string]string{"app.kubernetes.io/name": d.Name}),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:      "nim",
						Image:     d.Image,
						Env:       envVars,
						Resources: resources,
						Ports: []corev1.ContainerPort{{
							Name:          "http",
							ContainerPort: d.Port,
							Protocol:      corev1.ProtocolTCP,
						}},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path: "/v1/health/ready",
									Port: intstrFromInt(int(d.Port)),
								},
							},
							PeriodSeconds:    10,
							FailureThreshold: 3,
						},
					}},
				},
			},
		},
	}
}

// mergeLabels returns a new map containing every kv from base plus
// every kv from extra (extra wins on conflict). Both inputs may be nil.
func mergeLabels(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func firstContainerImage(d *appsv1.Deployment) string {
	if len(d.Spec.Template.Spec.Containers) == 0 {
		return ""
	}
	return d.Spec.Template.Spec.Containers[0].Image
}

func firstContainerPort(d *appsv1.Deployment) int32 {
	if len(d.Spec.Template.Spec.Containers) == 0 || len(d.Spec.Template.Spec.Containers[0].Ports) == 0 {
		return 0
	}
	return d.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort
}

func specReplicas(d *appsv1.Deployment) int32 {
	if d.Spec.Replicas == nil {
		return 0
	}
	return *d.Spec.Replicas
}
