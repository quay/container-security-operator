package labeller

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	log "github.com/go-kit/kit/log"
	"github.com/stretchr/testify/assert"

	secscanv1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	"github.com/quay/container-security-operator/prometheus"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/secscanfakes"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

func testVulnerableLayer() *secscan.Layer {
	var vulnerableTestLayer = &secscan.Layer{
		IndexedByVersion: 1,
		NamespaceName:    "debian:9",
		ParentName:       "SomeLayerName",
		Name:             "SomeOtherLayerName",
		Features: []*secscan.Feature{
			{
				Name:          "Some package name",
				VersionFormat: "dpkg",
				NamespaceName: "debian:9",
				AddedBy:       "SomeLayerIDThatIntroducedThisPackage",
				Version:       "2.24-11+deb9u4",
				Vulnerabilities: []*secscan.Vulnerability{
					{
						Severity:      "High",
						NamespaceName: "debian:9",
						Link:          "https://security-tracker.debian.org/tracker/CVE-1234-5678",
						Description:   "Some description",
						Name:          "CVE-1234-5678",
						Metadata: json.RawMessage(`{
						NVD: {
							CVSSv2: {
								Score:   7.8,
								Vectors: "AV:N/AC:L/Au:N/C:N/I:N",
							},
						},
					}`),
					},
				},
			},
		},
	}
	return vulnerableTestLayer
}

func testLayer() *secscan.Layer {
	var testLayer = &secscan.Layer{
		IndexedByVersion: 1,
		NamespaceName:    "debian:9",
		ParentName:       "SomeLayerName",
		Name:             "SomeOtherLayerName",
		Features: []*secscan.Feature{
			{
				Name:          "Some package name",
				VersionFormat: "dpkg",
				NamespaceName: "debian:9",
				AddedBy:       "SomeLayerIDThatIntroducedThisPackage",
				Version:       "2.24-11+deb9u4",
			},
		},
	}
	return testLayer
}

func testEmptyLayer() *secscan.Layer {
	var testLayer = &secscan.Layer{}
	return testLayer
}

func setupFakeSecscanInterface(c *testClient, layerFunc func() *secscan.Layer) {
	// Setup a fake WellknownInterface
	fakeWellknownInterface := &secscanfakes.FakeWellknownInterface{}
	fakeWellknownInterface.ManifestSecurityTemplateReturns("https://localhost/api/v1/repository/{namespace}/{reponame}/manifest/{digest}/security", nil)
	fakeWellknownInterface.ImageSecurityTemplateReturns("https://localhost/api/v1/repository/{namespace}/{reponame}/image/{imageid}/security", nil)
	fakeWellknownInterface.ViewImageTemplateReturns("https://localhost/{namespace}/{reponame}:{tag}", nil)

	c.secscanClient.WellknownReturns(fakeWellknownInterface, nil)
	c.secscanClient.GetLayerDataFromTemplateReturns(layerFunc(), nil)
}

func newConfigForTest(namespaces []string, interval, resyncThreshold time.Duration, labelPrefix, prometheusAddr, wellknownEndpoint string) *Config {
	return &Config{
		Namespaces:        namespaces,
		Interval:          interval,
		ResyncThreshold:   resyncThreshold,
		LabelPrefix:       labelPrefix,
		PrometheusAddr:    prometheusAddr,
		WellknownEndpoint: wellknownEndpoint,
	}
}

func newFakeLabeller(ctx context.Context, c *testClient, config *Config) *Labeller {
	l := &Labeller{
		logger: log.NewNopLogger(),

		kclient:           c.kclient,
		sclient:           c.sclient,
		secscanClient:     c.secscanClient,
		namespaces:        config.Namespaces,
		labelPrefix:       config.LabelPrefix,
		resyncPeriod:      config.Interval,
		resyncThreshold:   config.ResyncThreshold,
		wellKnownEndpoint: config.WellknownEndpoint,
		prometheus:        prometheus.NewServer(config.PrometheusAddr),

		queue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "fakeLabeller"),
	}

	podListWatcher := NewMultiNamespaceListerWatcher(
		l.namespaces,
		func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return l.kclient.CoreV1().Pods(namespace).List(options)
				},
				WatchFunc: l.kclient.CoreV1().Pods(namespace).Watch,
			}
		},
	)
	l.podInformer = cache.NewSharedIndexInformer(
		podListWatcher,
		&corev1.Pod{},
		l.resyncPeriod,
		cache.Indexers{},
	)
	l.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    l.handleAddPod,
		DeleteFunc: l.handleDeletePod,
		UpdateFunc: l.handleUpdatePod,
	})

	imageManifestVulnListWatcher := NewMultiNamespaceListerWatcher(
		l.namespaces,
		func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					return l.sclient.SecscanV1alpha1().ImageManifestVulns(namespace).List(options)
				},
				WatchFunc: l.sclient.SecscanV1alpha1().ImageManifestVulns(namespace).Watch,
			}
		},
	)
	l.imageManifestVulnInformer = cache.NewSharedIndexInformer(
		imageManifestVulnListWatcher,
		&secscanv1alpha1.ImageManifestVuln{},
		l.resyncPeriod,
		cache.Indexers{},
	)
	l.imageManifestVulnInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    l.handleAddImageManifestVuln,
		DeleteFunc: l.handleDeleteImageManifestVuln,
		UpdateFunc: l.handleUpdateImageManifestVuln,
	})

	for _, ns := range config.Namespaces {
		_, err := l.kclient.CoreV1().Namespaces().Create(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
		if err != nil && !k8serrors.IsAlreadyExists(err) {
			return nil
		}
	}

	// Start the informers without starting the reconciliation loop
	go l.podInformer.Run(ctx.Done())
	go l.imageManifestVulnInformer.Run(ctx.Done())
	if err := l.waitForCacheSync(ctx.Done()); err != nil {
		return nil
	}

	return l
}

func createRunningPod(t *testing.T, c *testClient, ns, name string, imageIDs []string) *corev1.Pod {
	runningPod, err := generatePod(ns, name, imageIDs, corev1.PodRunning)
	if err != nil {
		t.Fatal(err)
	}
	readyPodCondition := corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue}
	runningPod.Status.Conditions = append(runningPod.Status.Conditions, readyPodCondition)

	runningPod, err = c.createPod(runningPod)
	if err != nil {
		t.Fatal(err)
	}
	return runningPod
}

// TestSkipNonRunningPod tests that non-running pods are skipped by the reconciliation logic
func TestSkipNonRunningPod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	ns := generateNamespaceForTest(t)
	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}

	c := newTestClient()

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create pods that should not be scanned
	pod, _ := generatePod(ns, "Test-Pending-Pod", imageIDs, corev1.PodPending)
	pendingPod, _ := c.createPod(pod)
	pod, _ = generatePod(ns, "Test-Succeeded-Pod", imageIDs, corev1.PodSucceeded)
	succeededPod, _ := c.createPod(pod)
	pod, _ = generatePod(ns, "Test-Failed-Pod", imageIDs, corev1.PodFailed)
	failedPod, _ := c.createPod(pod)
	pod, _ = generatePod(ns, "Test-Unknown-Pod", imageIDs, corev1.PodUnknown)
	unknownPod, _ := c.createPod(pod)
	pods := []*corev1.Pod{pendingPod, succeededPod, failedPod, unknownPod}
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	for _, pod := range pods {
		err := fakeLabeller.Reconcile(pod.Namespace + "/" + pod.Name)
		if assert.Error(t, err) {
			if pod.Status.Phase == corev1.PodRunning {
				assert.Equal(t, err, fmt.Errorf("Pod condition not ready"))
			} else {
				assert.Equal(t, err, fmt.Errorf("Pod phase not running: %s", pod.Status.Phase))
			}
		}
	}
}

// TestNonVulnerablePod tests that a pod without vulnerable features running will not create a new ImageManifestVuln
func TestNonVulnerablePod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}
	ns := generateNamespaceForTest(t)

	c := newTestClient()
	setupFakeSecscanInterface(c, testLayer)

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create a running pod
	runningPod := createRunningPod(t, c, ns, "Test-Running-Pod", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err := fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Get the associated manifest and check the pod was added
	_, err = c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	if assert.Error(t, err) {
		assert.True(t, k8serrors.IsNotFound(err))
	}
}

// TestVulnerablePodCreateImageManifestVuln tests that vulnerable running pod will create a new ImageManifestVuln
func TestVulnerablePodCreateImageManifestVuln(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}
	ns := generateNamespaceForTest(t)

	c := newTestClient()
	setupFakeSecscanInterface(c, testVulnerableLayer)

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create a running pod
	runningPod := createRunningPod(t, c, ns, "Test-Running-Pod", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err := fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Get the associated manifest and check the pod was added
	manifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	_, ok := manifest.Status.AffectedPods[runningPod.Namespace+"/"+runningPod.Name]
	assert.True(t, ok)
}

// TestVulnerablePodUpdateImageManifestVuln tests that vulnerable running pod will update an existing ImageManifestVuln
func TestVulnerablePodUpdateImageManifestVuln(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}
	ns := generateNamespaceForTest(t)

	c := newTestClient()
	setupFakeSecscanInterface(c, testVulnerableLayer)

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create running pod
	runningPod1 := createRunningPod(t, c, ns, "Test-Running-Pod-1", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err := fakeLabeller.Reconcile(runningPod1.Namespace + "/" + runningPod1.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Check that the manifest has been created
	_, err = c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)

	// Create another running pod
	runningPod2 := createRunningPod(t, c, ns, "Test-Running-Pod-2", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err = fakeLabeller.Reconcile(runningPod2.Namespace + "/" + runningPod2.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Get the associated manifest and check the pod was added
	manifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	_, ok1 := manifest.Status.AffectedPods[runningPod1.Namespace+"/"+runningPod1.Name]
	_, ok2 := manifest.Status.AffectedPods[runningPod2.Namespace+"/"+runningPod2.Name]
	assert.True(t, ok1)
	assert.True(t, ok2)
}

// TestForcedResyncThreshold tests that vulnerable running pod will resync its ImageManifestVulns if its timestamp is older than the configured threshold
func TestForcedResyncThreshold(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}
	ns := generateNamespaceForTest(t)

	c := newTestClient()
	setupFakeSecscanInterface(c, testVulnerableLayer)

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create a running pod
	runningPod := createRunningPod(t, c, ns, "Test-Running-Pod", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err := fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Get the associated manifest
	manifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	initialTimestamp, _ := lastManfestUpdateTime(manifest)

	// Resyncing a pod too early should have no effects
	err = fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	manifest, err = c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	sameInitialTimestamp, _ := lastManfestUpdateTime(manifest)
	assert.Equal(t, initialTimestamp, sameInitialTimestamp)

	// Set the ImageManifestVuln's lastUpdate to force a resync
	expiredTime := time.Now().UTC().Add(-2 * fakeLabeller.resyncThreshold)
	manifest.Status.LastUpdate = expiredTime.String()
	_, err = c.updateManifestStatus(manifest)
	assert.NoError(t, err)

	// Rescan the pod and check for new lastUpdate
	err = fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	updatedManifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	newTimestamp, _ := lastManfestUpdateTime(updatedManifest)
	assert.True(t, newTimestamp.After(*initialTimestamp))
}

// TestGarbageCollectManifest tests that ImageManifestVulns are garbage collected when pods are deleted
func TestGarbageCollectManifest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}
	ns := generateNamespaceForTest(t)

	c := newTestClient()
	setupFakeSecscanInterface(c, testVulnerableLayer)

	fakeLabeller := newFakeLabeller(ctx, c, newConfigForTest([]string{ns}, 5*time.Minute, 5*time.Minute, "testLabel", ":8081", ".well-known/app-capabilities"))

	// Create a running pod
	runningPod := createRunningPod(t, c, ns, "Test-Running-Pod", imageIDs)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Scan the pod
	err := fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Get the associated manifest and check for pod reference
	manifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	assert.NoError(t, err)
	_, ok := manifest.Status.AffectedPods[runningPod.Namespace+"/"+runningPod.Name]
	assert.True(t, ok)

	// Delete the pod
	assert.NoError(t, c.deletePod(runningPod.Namespace, runningPod.Name, &metav1.DeleteOptions{}))
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Delete event reconciliation
	err = fakeLabeller.Reconcile(runningPod.Namespace + "/" + runningPod.Name)
	assert.NoError(t, err)
	assert.NoError(t, fakeLabeller.waitForCacheSync(ctx.Done()))

	// Check that the pod reference was deleted
	_, err = c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	if assert.Error(t, err) {
		assert.True(t, k8serrors.IsNotFound(err))
	}
}
