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
	// OwnerReferences is included so Deployments created before owner-
	// reference stamping was added get adopted on their next reconcile.
	existing.Labels = desired.Labels
	existing.OwnerReferences = desired.OwnerReferences
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

	// Resource requests+limits. GPU is always set from NIMService.Spec.
	// CPU + memory REQUESTS default to Tuesday's hardening baseline
	// (500m + 2Gi) and are overridable per NIMService via Spec.Resources;
	// CPU + memory LIMITS default to unset (Burstable-QoS by design —
	// no ceiling means a NIM whose real usage exceeds a hardcoded limit
	// isn't OOMKilled by the operator, only by node exhaustion) and are
	// also settable per NIMService when the operator has verified a
	// specific workload's ceiling.
	//
	// The default → override precedence is intentional: empty
	// d.CPURequest/MemoryRequest keeps Tuesday's numbers byte-identical
	// for existing NIMService CRs that don't set Spec.Resources, so
	// this addition is strictly additive. Empty d.CPULimit/MemoryLimit
	// keeps "no LIMIT" — the specific choice Tuesday made and peer
	// endorsed as safer than a hardcoded ceiling.
	cpuReqStr := d.CPURequest
	if cpuReqStr == "" {
		cpuReqStr = "500m"
	}
	memReqStr := d.MemoryRequest
	if memReqStr == "" {
		memReqStr = "2Gi"
	}
	resources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			"nvidia.com/gpu": *resource.NewQuantity(int64(d.GPURequest), resource.DecimalSI),
		},
		Requests: corev1.ResourceList{
			"nvidia.com/gpu":      *resource.NewQuantity(int64(d.GPURequest), resource.DecimalSI),
			corev1.ResourceCPU:    resource.MustParse(cpuReqStr),
			corev1.ResourceMemory: resource.MustParse(memReqStr),
		},
	}
	if d.CPULimit != "" {
		resources.Limits[corev1.ResourceCPU] = resource.MustParse(d.CPULimit)
	}
	if d.MemoryLimit != "" {
		resources.Limits[corev1.ResourceMemory] = resource.MustParse(d.MemoryLimit)
	}

	// Pod- and container-level hardening. Defaults are Tuesday's
	// baseline — safe to apply without operator opt-in. The per-
	// NIMService overrides for ReadOnlyRootFilesystem + WritableMounts
	// land here as opt-in additions on top of the baseline.
	//
	//   Pod (always on):
	//     - runAsNonRoot: true — kubelet rejects pods whose image USER
	//       is 0; misconfigured images fail loudly instead of silently.
	//     - seccompProfile: RuntimeDefault — required for
	//       PodSecurityStandards restricted profile admission.
	//     - automountServiceAccountToken: false — NIM does not call the
	//       K8s API; mounting the SA token is an exfil surface for a
	//       jailbroken workload.
	//
	//   Container (always on):
	//     - allowPrivilegeEscalation: false
	//     - capabilities.drop [ALL]
	//
	//   Container (opt-in via Spec.ReadOnlyRootFilesystem):
	//     - readOnlyRootFilesystem: true
	//     - emptyDir volumes at each Spec.WritableMounts path; default
	//       WritableMounts=["/tmp"] when the list is empty. That
	//       default is a GUESS based on the general NIM shape and has
	//       not been verified against a specific image (NIM images may
	//       need /var/cache, /root/.cache, etc.). The operator sets
	//       WritableMounts explicitly for a verified image. See the
	//       NIMServiceSpec.WritableMounts godoc for the reasoning.
	//
	// STILL DEFERRED to a follow-up (recorded so the rendered pod's
	// hardening state stays honest to the reader):
	//   - Full corev1.SecurityContext passthrough (runAsUser override,
	//     seccomp override, capabilities.add). Requires plain-Go mirror
	//     types for every field to preserve the pure-reconciler split;
	//     real CRD schema work.
	//   - Per-NIMService NetworkPolicy — governance concern layered at
	//     aigov chart level, not renderable here.
	nonRoot := true
	noPrivEsc := false
	replicas := d.Replicas

	// WritableMounts default: peer's key correction to my scope proposal
	// — never hardcode the mount path inside the adapter, because it
	// makes an unverifiable assumption about NIM's write set. Instead
	// default the empty list to ["/tmp"] AT USE SITE only when
	// ReadOnlyRootFilesystem is on, so operators who verified their
	// image can override the default and operators who leave it get a
	// documented-guess starting point.
	writableMounts := d.WritableMounts
	if d.ReadOnlyRootFilesystem && len(writableMounts) == 0 {
		writableMounts = []string{"/tmp"}
	}

	containerSecCtx := &corev1.SecurityContext{
		AllowPrivilegeEscalation: &noPrivEsc,
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
		},
	}
	var volumes []corev1.Volume
	var volumeMounts []corev1.VolumeMount
	if d.ReadOnlyRootFilesystem {
		readOnly := true
		containerSecCtx.ReadOnlyRootFilesystem = &readOnly
		volumes = make([]corev1.Volume, 0, len(writableMounts))
		volumeMounts = make([]corev1.VolumeMount, 0, len(writableMounts))
		for i, path := range writableMounts {
			volName := fmt.Sprintf("writable-%d", i)
			volumes = append(volumes, corev1.Volume{
				Name:         volName,
				VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
			})
			volumeMounts = append(volumeMounts, corev1.VolumeMount{
				Name:      volName,
				MountPath: path,
			})
		}
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            d.Name,
			Namespace:       d.Namespace,
			Labels:          labels,
			OwnerReferences: ownerReferences(d),
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
					AutomountServiceAccountToken: &noPrivEsc, // false
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &nonRoot,
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Volumes: volumes,
					Containers: []corev1.Container{{
						Name:            "nim",
						Image:           d.Image,
						Env:             envVars,
						Resources:       resources,
						VolumeMounts:    volumeMounts,
						SecurityContext: containerSecCtx,
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

// ownerReferences returns the single OwnerReference tying the rendered
// Deployment to its NIMService, or nil when d carries no OwnerUID (a
// plain-Go Deployment built outside a live cluster). Controller+
// BlockOwnerDeletion are both true so the API server's GC deletes this
// Deployment when the NIMService is deleted, and refuses to delete the
// NIMService first while the Deployment still references it.
func ownerReferences(d *controller.Deployment) []metav1.OwnerReference {
	if d.OwnerUID == "" {
		return nil
	}
	isController := true
	blockDeletion := true
	return []metav1.OwnerReference{{
		APIVersion:         v1alpha1.GroupVersion.String(),
		Kind:               "NIMService",
		Name:               d.Name,
		UID:                types.UID(d.OwnerUID),
		Controller:         &isController,
		BlockOwnerDeletion: &blockDeletion,
	}}
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
