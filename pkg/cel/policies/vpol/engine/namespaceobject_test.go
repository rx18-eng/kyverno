package engine

import (
	"context"
	"testing"

	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	celengine "github.com/kyverno/kyverno/pkg/cel/engine"
	"github.com/kyverno/kyverno/pkg/cel/matching"
	"github.com/kyverno/kyverno/pkg/cel/policies/vpol/compiler"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// A ValidatingPolicy whose matchCondition reads namespaceObject.metadata.labels must not error when
// the namespace resolver cannot return the namespace (an informer cache miss). Before the fix,
// namespaceObject was null and the expression failed with "no such key: metadata", which under a Deny
// action rejected every request. See issue #16518. The matchCondition and CronJob mirror the report.
func TestHandle_NamespaceObjectResolvesWhenResolverReturnsNil(t *testing.T) {
	policy := &policiesv1beta1.ValidatingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "cronjob-cpu-requests-equal-limits"},
		Spec: policiesv1beta1.ValidatingPolicySpec{
			ValidationAction: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{"batch"},
							APIVersions: []string{"v1"},
							Resources:   []string{"cronjobs"},
						},
					},
				}},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{{
				Name:       "namespace-selector",
				Expression: "'acme.app/resource-tier' in namespaceObject.metadata.labels && namespaceObject.metadata.labels['acme.app/resource-tier'] == 'guaranteed'",
			}},
			Validations: []admissionregistrationv1.Validation{{
				Expression: "true",
				Message:    "placeholder",
			}},
		},
	}

	provider, err := NewProvider(compiler.NewCompiler(), []policiesv1beta1.ValidatingPolicyLike{policy}, nil)
	require.NoError(t, err)

	cronjob := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "CronJob",
		"metadata":   map[string]any{"name": "hello", "namespace": "team-a"},
		"spec":       map[string]any{"schedule": "* * * * *"},
	}}
	newRequest := func() celengine.EngineRequest {
		return celengine.Request(
			nil,
			schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"},
			schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"},
			"", "hello", "team-a",
			admissionv1.Create, authenticationv1.UserInfo{}, cronjob, nil, false, nil,
		)
	}

	statusOf := func(resp EngineResponse) engineapi.RuleStatus {
		require.Len(t, resp.Policies, 1)
		require.Len(t, resp.Policies[0].Rules, 1)
		return resp.Policies[0].Rules[0].Status()
	}

	// resolver returns nil (cache miss): the matchCondition must evaluate cleanly instead of erroring.
	// The minimal namespace has no acme.app/resource-tier label, so the policy does not match (skip).
	engNil := NewEngine(provider, func(string) *corev1.Namespace { return nil }, matching.NewMatcher())
	respNil, err := engNil.Handle(context.Background(), newRequest(), nil)
	require.NoError(t, err)
	require.NotEqual(t, engineapi.RuleStatusError, statusOf(respNil), "namespaceObject must not error on a resolver miss")

	// resolver returns the real namespace carrying the label: the policy matches and validates.
	engOK := NewEngine(provider, func(name string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"acme.app/resource-tier": "guaranteed"},
		}}
	}, matching.NewMatcher())
	respOK, err := engOK.Handle(context.Background(), newRequest(), nil)
	require.NoError(t, err)
	require.Equal(t, engineapi.RuleStatusPass, statusOf(respOK))
}
