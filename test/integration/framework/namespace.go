package framework

import (
	"context"

	"github.com/kyverno/kyverno/pkg/cel/engine"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// newNamespaceResolver returns a NamespaceResolver backed by the manager's cache, so integration
// tests can exercise namespaceObject and namespaceSelector against a namespace's real labels rather
// than always seeing an empty namespace. It returns nil on a miss, matching the production resolver.
func newNamespaceResolver(mgr ctrl.Manager) engine.NamespaceResolver {
	return func(name string) *corev1.Namespace {
		var ns corev1.Namespace
		if err := mgr.GetClient().Get(context.Background(), client.ObjectKey{Name: name}, &ns); err != nil {
			return nil
		}
		return &ns
	}
}
