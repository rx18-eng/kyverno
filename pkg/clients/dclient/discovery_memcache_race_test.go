package dclient

import (
	"testing"
	"time"

	openapi_v2 "github.com/google/gnostic-models/openapiv2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/openapi"
	restclient "k8s.io/client-go/rest"
)

// flippingDiscovery is a real AggregatedDiscoveryInterface whose resource
// list flips at readyAt; other methods panic, unused by this refresh path.
type flippingDiscovery struct {
	gv       schema.GroupVersion
	kind     string
	resource string
	readyAt  time.Time
	calls    int
}

func (f *flippingDiscovery) GroupsAndMaybeResources() (*metav1.APIGroupList, map[schema.GroupVersion]*metav1.APIResourceList, map[schema.GroupVersion]error, error) {
	f.calls++
	groups := &metav1.APIGroupList{}
	resources := map[schema.GroupVersion]*metav1.APIResourceList{}
	if !time.Now().Before(f.readyAt) {
		groups.Groups = append(groups.Groups, metav1.APIGroup{
			Name: f.gv.Group,
			Versions: []metav1.GroupVersionForDiscovery{
				{GroupVersion: f.gv.String(), Version: f.gv.Version},
			},
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: f.gv.String(), Version: f.gv.Version},
		})
		resources[f.gv] = &metav1.APIResourceList{
			GroupVersion: f.gv.String(),
			APIResources: []metav1.APIResource{
				{Name: f.resource, Kind: f.kind, Group: f.gv.Group, Version: f.gv.Version, Namespaced: true},
			},
		}
	}
	return groups, resources, nil, nil
}

func (f *flippingDiscovery) RESTClient() restclient.Interface { return nil }
func (f *flippingDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) ServerResourcesForGroupVersion(string) (*metav1.APIResourceList, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) ServerPreferredNamespacedResources() ([]*metav1.APIResourceList, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) ServerVersion() (*version.Info, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) OpenAPISchema() (*openapi_v2.Document, error) {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) OpenAPIV3() openapi.Client {
	panic("not used by the aggregated refresh path")
}

func (f *flippingDiscovery) WithLegacy() discovery.DiscoveryInterface {
	panic("not used by the aggregated refresh path")
}

var _ discovery.AggregatedDiscoveryInterface = &flippingDiscovery{}

// TestGetGVRFromGVK_StaleCacheSurvivesRetriesWithoutExternalInvalidate: a
// refresh that lands before the server is ready caches the miss as valid,
// and retrying GetGVRFromGVK alone never asks the server again.
func TestGetGVRFromGVK_StaleCacheSurvivesRetriesWithoutExternalInvalidate(t *testing.T) {
	otherGVK := schema.GroupVersionKind{Group: "example.io", Version: "v1", Kind: "Warmup"}
	targetGVK := schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}
	fake := &flippingDiscovery{
		gv:       schema.GroupVersion{Group: "cilium.io", Version: "v2"},
		kind:     "CiliumNetworkPolicy",
		resource: "ciliumnetworkpolicies",
		readyAt:  time.Now().Add(200 * time.Millisecond),
	}
	disco := NewServerResourcesDiscovery(fake)

	// Warm the cache on an unrelated GVK, as if some earlier lookup had
	// already populated it before the CRD existed.
	_, _ = disco.GetGVRFromGVK(otherGVK)
	require.True(t, disco.CachedDiscoveryInterface().Fresh())

	// The CRD watcher fires (t0): invalidate, exactly like
	// serverResources.CreateCRDWatcher's AddFunc/UpdateFunc do.
	disco.CachedDiscoveryInterface().Invalidate()
	disco.RESTMapper().(meta.ResettableRESTMapper).Reset()

	// A refetch happens immediately, before readyAt: this is the race.
	_, err := disco.GetGVRFromGVK(targetGVK)
	require.Error(t, err)

	// Retrying alone, however long, must never recover: the cache is
	// "fresh" (valid) even though it is missing the CRD.
	for i := 0; i < 5; i++ {
		time.Sleep(80 * time.Millisecond)
		_, err = disco.GetGVRFromGVK(targetGVK)
		assert.Error(t, err, "a stale-but-fresh cache must not self-heal from retries alone")
	}
	require.True(t, time.Now().After(fake.readyAt), "test setup: retries above must have crossed readyAt")
	callsAfterRetries := fake.calls

	// Only an explicit external invalidate (the fix under test) recovers.
	disco.CachedDiscoveryInterface().Invalidate()
	disco.RESTMapper().(meta.ResettableRESTMapper).Reset()
	gvr, err := disco.GetGVRFromGVK(targetGVK)
	require.NoError(t, err)
	assert.Equal(t, "ciliumnetworkpolicies", gvr.Resource)
	assert.Greater(t, fake.calls, callsAfterRetries, "an explicit invalidate must trigger a fresh server call")
}
