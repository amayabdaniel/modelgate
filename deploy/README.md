# Deploy Manifests

Kubernetes manifests for running the NIM operator and declaring
`NIMService` resources in a cluster.

## Layout

- `crd/nimservice.yaml` — CustomResourceDefinition for `NIMService`.
  Includes the OpenAPI schema, `status` + `scale` subresources, and
  printer columns for `kubectl get nim`.
- `operator.yaml` — Namespace, ServiceAccount, ClusterRole /
  ClusterRoleBinding, and Deployment for the operator itself. Points
  at `ghcr.io/amayabdaniel/nim-operator:latest` — retag if you push
  the image to a different registry.
- `examples/nimservice-llama3.yaml` — a realistic NIMService plus its
  NGC secret placeholder. Copy, replace the secret value, and apply.

## Bootstrap

```
# 1. Install the CRD.
kubectl apply -f deploy/crd/nimservice.yaml
kubectl get crd nimservices.modelgate.dev

# 2a. Local dev (out-of-cluster, uses current kubectl context):
make operator-run

# 2b. In-cluster deploy (uses the published operator image):
make operator-image                     # build + tag ghcr.io/amayabdaniel/nim-operator:latest
docker push ghcr.io/amayabdaniel/nim-operator:latest
kubectl apply -f deploy/operator.yaml
kubectl -n nim-operator-system get pods
```

Once the CRD is installed and the operator is running:

```
kubectl apply -f deploy/examples/nimservice-llama3.yaml
kubectl get nim
# NAME        MODEL                REPLICAS   READY   PHASE
# llama3-8b   llama3-8b-instruct   2          0       Pending
```

The operator materializes an `apps/v1.Deployment` for the pods,
projects `NGC_API_KEY` from the referenced Secret, requests
`nvidia.com/gpu` resources, and drives the `NIMService` status through
`Pending → Progressing → Ready` as pods pass the `/v1/health/ready`
probe. `Degraded` shows up when the spec fails validation; the
`NGCKeyPresent` condition surfaces when `ngcSecretName` is omitted.

## Scale operations

Because the CRD declares a `scale` subresource, standard kubectl
scaling works:

```
kubectl scale nim/llama3-8b --replicas=4
kubectl scale nim/llama3-8b --replicas=0   # explicit scale-to-zero, honored
```

The pointer-typed Replicas field in `api/v1alpha1/nimservice.go`
distinguishes "field omitted" from "explicit 0" — the operator's
defaulting logic preserves that intent.
