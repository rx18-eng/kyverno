package engine

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestResolveNamespace(t *testing.T) {
	realNS := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{"acme.app/resource-tier": "guaranteed"},
		},
	}

	t.Run("cluster-scoped request returns nil", func(t *testing.T) {
		got := ResolveNamespace(func(string) *corev1.Namespace { return realNS }, "")
		assert.Nil(t, got)
	})

	t.Run("resolver hit returns the real namespace with its labels", func(t *testing.T) {
		got := ResolveNamespace(func(string) *corev1.Namespace { return realNS }, "team-a")
		assert.Equal(t, "team-a", got.Name)
		assert.Equal(t, "guaranteed", got.Labels["acme.app/resource-tier"])
	})

	t.Run("resolver miss falls back to a minimal namespace", func(t *testing.T) {
		got := ResolveNamespace(func(string) *corev1.Namespace { return nil }, "team-a")
		assert.Equal(t, "team-a", got.Name)
		assert.Equal(t, "team-a", got.Labels["kubernetes.io/metadata.name"])
	})
}
