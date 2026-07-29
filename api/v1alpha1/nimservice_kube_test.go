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
