//go:build k8s

// nim-operator is the controller-runtime binary that reconciles
// NIMService resources in a Kubernetes cluster. It boots a Manager,
// registers our types with a scheme, and wires the pure-Go reconciler
// (internal/controller.Reconciler) behind a controller-runtime
// Reconciler shape via kubeReconciler.
//
// Build with:
//   go build -tags k8s -o bin/nim-operator ./cmd/nim-operator
//
// Run in-cluster:
//   ./bin/nim-operator
//
// The default build of modelgate (proxy binary) omits everything in
// this directory — no k8s deps in the proxy container.
package main

import (
	"context"
	"flag"
	"os"

	"github.com/amayabdaniel/modelgate/api/v1alpha1"
	"github.com/amayabdaniel/modelgate/internal/controller"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(appsv1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr, probeAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Prometheus metrics bind address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe bind address")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "nim-operator-leader.modelgate.dev",
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Wire the pure-Go reconciler through the kubeClient adapter, then
	// wrap it in a controller-runtime Reconciler that owns the queue.
	pureRecon := controller.NewReconciler(newKubeClient(mgr.GetClient()))

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.KubeNIMService{}).
		Owns(&appsv1.Deployment{}).
		Complete(&kubeReconciler{inner: pureRecon}); err != nil {
		setupLog.Error(err, "unable to create NIMService controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", nil); err != nil {
		setupLog.Error(err, "add healthz")
	}
	if err := mgr.AddReadyzCheck("readyz", nil); err != nil {
		setupLog.Error(err, "add readyz")
	}

	setupLog.Info("starting NIM operator manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// kubeReconciler bridges controller-runtime's Reconciler interface
// (reconcile.Request in, reconcile.Result out) to our simple
// namespace/name reconcile call. All the actual logic lives in the
// pure-Go Reconciler — this is just I/O plumbing.
type kubeReconciler struct {
	inner *controller.Reconciler
}

func (r *kubeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if err := r.inner.Reconcile(ctx, req.Namespace, req.Name); err != nil {
		// controller-runtime will re-queue with exponential backoff.
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}
