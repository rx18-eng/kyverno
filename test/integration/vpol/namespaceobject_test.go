//go:build integration

package vpol_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	policiesv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	vpol "github.com/kyverno/kyverno/pkg/webhooks/resource/vpol"
	"github.com/kyverno/kyverno/test/integration/framework"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// tierGatedCronJobPolicy is the policy shape from issue #16518: a CronJob cpu policy that only
// applies to namespaces labelled as the guaranteed resource tier, gated on
// namespaceObject.metadata.labels from a matchCondition.
func tierGatedCronJobPolicy(name string) *policiesv1beta1.ValidatingPolicy {
	return &policiesv1beta1.ValidatingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: policiesv1beta1.ValidatingPolicySpec{
			MatchConstraints: framework.CronJobMatchRules(),
			MatchConditions: []admissionregistrationv1.MatchCondition{{
				Name:       "guaranteed-tier-namespaces-only",
				Expression: "'acme.app/resource-tier' in namespaceObject.metadata.labels && namespaceObject.metadata.labels['acme.app/resource-tier'] == 'guaranteed'",
			}},
			Validations: []admissionregistrationv1.Validation{{
				Expression: "object.spec.jobTemplate.spec.template.spec.containers.all(c, has(c.resources) && has(c.resources.requests) && has(c.resources.limits) && c.resources.requests.cpu == c.resources.limits.cpu)",
				Message:    "cpu requests must equal cpu limits",
			}},
			ValidationAction: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
		},
	}
}

// burstableCronJob asks for 100m cpu but is capped at 500m, so it fails the policy above whenever
// the policy applies to its namespace.
func burstableCronJob(namespace string) []byte {
	return []byte(fmt.Sprintf(`{
		"apiVersion": "batch/v1", "kind": "CronJob",
		"metadata": {"name": "nightly-billing-report", "namespace": %q},
		"spec": {
			"schedule": "0 2 * * *",
			"jobTemplate": {"spec": {"template": {"spec": {
				"restartPolicy": "OnFailure",
				"containers": [{
					"name": "report",
					"image": "acme/billing-report:1.4.2",
					"resources": {
						"requests": {"cpu": "100m", "memory": "128Mi"},
						"limits": {"cpu": "500m", "memory": "128Mi"}
					}
				}]
			}}}}
		}
	}`, namespace))
}

// waitForNamespaceInCache waits until the manager cache, which is the cache the engine's namespace
// resolver reads, can see the namespace. Without this the resolver races the cache and falls back
// to a minimal namespace, so the test would pass without ever reading the real labels.
func waitForNamespaceInCache(t *testing.T, name string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var ns corev1.Namespace
		return testEnv.Client.Get(context.Background(), client.ObjectKey{Name: name}, &ns) == nil
	}, 5*time.Second, 100*time.Millisecond, "namespace %s never became visible in the manager cache", name)
}

func TestValidate_NamespaceObject_PolicyAppliesOnlyToNamespacesWithMatchingLabel(t *testing.T) {
	// A platform team gates a cpu policy on a namespace label so it only applies to the guaranteed
	// tier. The cronjob submitted below is identical in both namespaces, so the namespace label
	// read through namespaceObject is the only thing deciding whether the policy applies.
	framework.CreateNamespaceWithLabels(t, testEnv.KubeClient, "acme-guaranteed", map[string]string{"acme.app/resource-tier": "guaranteed"})
	framework.CreateNamespaceWithLabels(t, testEnv.KubeClient, "acme-standard", map[string]string{"acme.app/resource-tier": "standard"})
	waitForNamespaceInCache(t, "acme-guaranteed")
	waitForNamespaceInCache(t, "acme-standard")

	createPolicyWithCleanup(t, tierGatedCronJobPolicy("cronjob-equal-requests-limits-cpu-require"))
	waitForPolicyReady(t, 1)

	h := vpol.New(engine, testEnv.ContextProvider, nil, false, &framework.MockEventGen{})

	resp := h.ValidateClustered(context.Background(), logr.Discard(),
		framework.CronJobAdmissionRequest("nightly-billing-report", "acme-guaranteed", burstableCronJob("acme-guaranteed")), "", time.Now())

	assert.False(t, resp.Allowed, "cronjob in the guaranteed tier namespace should be blocked")
	require.NotNil(t, resp.Result, "deny response should include result details")
	assert.Contains(t, resp.Result.Message, "cpu requests must equal cpu limits", "the block should come from the validation")
	assert.NotContains(t, resp.Result.Message, "no such key", "namespaceObject labels should resolve rather than error")

	// Same cronjob, namespace labelled standard: the match condition is false, so the policy does
	// not apply and the request is not evaluated at all.
	resp = h.ValidateClustered(context.Background(), logr.Discard(),
		framework.CronJobAdmissionRequest("nightly-billing-report", "acme-standard", burstableCronJob("acme-standard")), "", time.Now())

	assert.True(t, resp.Allowed, "cronjob in the standard tier namespace should not be evaluated by the policy")
}

func TestValidate_NamespaceObject_UnresolvableNamespaceDoesNotBlockAdmission(t *testing.T) {
	// Issue #16518: when the resolver could not return the namespace, namespaceObject reached CEL
	// as null and the match condition failed with "no such key: metadata". Under a Deny action that
	// error rejected every cronjob, including ones the policy was never meant to apply to.
	createPolicyWithCleanup(t, tierGatedCronJobPolicy("cronjob-equal-requests-limits-cpu-require-unresolved"))
	waitForPolicyReady(t, 1)

	h := vpol.New(engine, testEnv.ContextProvider, nil, false, &framework.MockEventGen{})

	resp := h.ValidateClustered(context.Background(), logr.Discard(),
		framework.CronJobAdmissionRequest("nightly-billing-report", "acme-unresolvable", burstableCronJob("acme-unresolvable")), "", time.Now())

	assert.True(t, resp.Allowed, "an unresolvable namespace should skip the policy rather than deny the request")
}
