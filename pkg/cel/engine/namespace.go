package engine

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NamespaceResolver = func(string) *corev1.Namespace

// ResolveNamespace returns the Namespace object for a namespaced request, or nil for a
// cluster-scoped one. When the resolver cannot return the namespace (an informer cache miss, or the
// CLI and test paths that have no cluster), it falls back to a minimal namespace so namespaceObject
// stays a usable object: a nil namespace reaches CEL as null, and a matchCondition reading
// namespaceObject.metadata then errors with "no such key: metadata", which under a Deny action
// rejects the request instead of skipping the policy.
//
// The kubernetes.io/metadata.name label carries its own weight here. ObjectMeta.Labels is
// omitempty, so a namespace with no labels serializes without the key at all and
// namespaceObject.metadata.labels errors the same way. A real API server labels every namespace
// with its own name, so the fallback matches what callers would have seen on a cache hit.
func ResolveNamespace(resolver NamespaceResolver, name string) *corev1.Namespace {
	if name == "" {
		return nil
	}
	if ns := resolver(name); ns != nil {
		return ns
	}
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"kubernetes.io/metadata.name": name},
		},
	}
}
