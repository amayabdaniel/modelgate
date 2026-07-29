//go:build k8s

// nimservice_kube.go carries the k8s.io metadata machinery for
// NIMService — DeepCopy, TypeMeta, scheme registration — so the type
// can be handled by controller-runtime.
//
// This file only compiles under `-tags k8s`. The default modelgate
// build (proxy binary) omits it entirely and keeps its dep tree lean.
// Only cmd/nim-operator/ is built with the tag.
//
// The pure-Go NIMService in nimservice.go stays authoritative; the
// KubeNIMService below is a thin metav1-aware wrapper the adapter
// converts to/from when moving data across the k8s client boundary.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// GroupVersion is the canonical GV for modelgate CRDs. Registered with
// the controller-runtime scheme at operator boot.
var GroupVersion = schema.GroupVersion{Group: "modelgate.dev", Version: "v1alpha1"}

// KubeNIMService is the k8s-native representation of NIMService — the
// shape a controller-runtime client returns from Get/List calls. The
// operator adapter converts it into the plain NIMService the pure-Go
// reconciler consumes.
type KubeNIMService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NIMServiceSpec   `json:"spec,omitempty"`
	Status            NIMServiceStatus `json:"status,omitempty"`
}

// KubeNIMServiceList is the collection type controller-runtime needs
// for Watch/List semantics.
type KubeNIMServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KubeNIMService `json:"items"`
}

// DeepCopyInto and DeepCopyObject satisfy runtime.Object. Ordinarily
// these are code-generated; hand-writing them keeps the operator
// build tag-only and avoids pulling k8s codegen into the main tree.

func (in *KubeNIMService) DeepCopyInto(out *KubeNIMService) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	// Spec/Status are value types with no reference fields (see
	// nimservice.go). Direct copy is safe; Conditions is a slice that
	// needs its own copy.
	if in.Spec.Replicas != nil {
		r := *in.Spec.Replicas
		out.Spec.Replicas = &r
	}
	if in.Status.Conditions != nil {
		out.Status.Conditions = make([]Condition, len(in.Status.Conditions))
		copy(out.Status.Conditions, in.Status.Conditions)
	}
}

func (in *KubeNIMService) DeepCopy() *KubeNIMService {
	if in == nil {
		return nil
	}
	out := new(KubeNIMService)
	in.DeepCopyInto(out)
	return out
}

func (in *KubeNIMService) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *KubeNIMServiceList) DeepCopyInto(out *KubeNIMServiceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KubeNIMService, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KubeNIMServiceList) DeepCopy() *KubeNIMServiceList {
	if in == nil {
		return nil
	}
	out := new(KubeNIMServiceList)
	in.DeepCopyInto(out)
	return out
}

func (in *KubeNIMServiceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// AddToScheme registers the NIMService types with a controller-runtime
// scheme. Called from cmd/nim-operator/main.go during Manager setup.
func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&KubeNIMService{},
		&KubeNIMServiceList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

// ToKubeNIMService converts the plain type back to the metav1-flavored
// one — the reconciler adapter uses this when writing status updates.
func ToKubeNIMService(src *NIMService) *KubeNIMService {
	if src == nil {
		return nil
	}
	labels := make(map[string]string, len(src.Metadata.Labels))
	for k, v := range src.Metadata.Labels {
		labels[k] = v
	}
	return &KubeNIMService{
		TypeMeta: metav1.TypeMeta{
			APIVersion: src.APIVersion,
			Kind:       src.Kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:       src.Metadata.Name,
			Namespace:  src.Metadata.Namespace,
			Labels:     labels,
			Generation: src.Metadata.Generation,
			UID:        types.UID(src.Metadata.UID),
		},
		Spec:   src.Spec,
		Status: src.Status,
	}
}

// FromKubeNIMService converts a controller-runtime read into the plain
// type the pure-Go reconciler consumes. The reverse of ToKubeNIMService.
func FromKubeNIMService(src *KubeNIMService) *NIMService {
	if src == nil {
		return nil
	}
	labels := make(map[string]string, len(src.Labels))
	for k, v := range src.Labels {
		labels[k] = v
	}
	return &NIMService{
		Kind:       src.Kind,
		APIVersion: src.APIVersion,
		Metadata: ObjectMeta{
			Name:       src.Name,
			Namespace:  src.Namespace,
			Labels:     labels,
			Generation: src.Generation,
			UID:        string(src.UID),
		},
		Spec:   src.Spec,
		Status: src.Status,
	}
}
