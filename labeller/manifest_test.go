package labeller

import (
	"context"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	icspclient "github.com/openshift/client-go/operator/clientset/versioned"
	fakeicspclient "github.com/openshift/client-go/operator/clientset/versioned/fake"
	secscanv1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	secscanclient "github.com/quay/container-security-operator/generated/clientset/versioned"
	fakesecscanclient "github.com/quay/container-security-operator/generated/clientset/versioned/fake"
	secscanv1alpha1client "github.com/quay/container-security-operator/generated/clientset/versioned/typed/secscan/v1alpha1"
	"github.com/quay/container-security-operator/image"
	"github.com/quay/container-security-operator/secscan/secscanfakes"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func randString(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// Generate a Pod in a given namespace based on a given imageID
func generatePod(namespace, name string, imageIDs []string, phase corev1.PodPhase) (*corev1.Pod, error) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{},
		},
		Status: corev1.PodStatus{
			Phase:             phase,
			Conditions:        []corev1.PodCondition{},
			ContainerStatuses: []corev1.ContainerStatus{},
		},
	}

	for _, imageID := range imageIDs {
		img, err := image.ParseImageID(imageID)
		if err != nil {
			return nil, err
		}

		img.ContainerID = "docker://" + randString(64)
		container := corev1.Container{
			Name:  img.ContainerName,
			Image: img.String(),
		}
		containerStatus := corev1.ContainerStatus{
			ContainerID: img.ContainerID,
			Name:        img.ContainerName,
			Image:       img.String(),
			ImageID:     imageID,
		}
		pod.Spec.Containers = append(pod.Spec.Containers, container)
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, containerStatus)
	}

	return pod, nil
}

// Generate an ImageManifestVuln in a given namespace based on a given set of Pods
func generateManifest(namespace, name string, pods []*corev1.Pod) (*secscanv1alpha1.ImageManifestVuln, error) {
	manifest := &secscanv1alpha1.ImageManifestVuln{
		ObjectMeta: metav1.ObjectMeta{
			Labels:    make(map[string]string),
			Namespace: namespace,
			Name:      name,
		},
		Spec: secscanv1alpha1.ImageManifestVulnSpec{
			Manifest: strings.Replace(name, ".", ":", 1),
		},
		Status: secscanv1alpha1.ImageManifestVulnStatus{
			AffectedPods: make(map[string][]string),
		},
	}

	for _, pod := range pods {
		containerIds := []string{}
		for _, containerStatus := range pod.Status.ContainerStatuses {
			img, err := image.ParseContainer(pod, containerStatus.Name)
			if err != nil {
				return nil, err
			}

			if img.Digest == manifest.Spec.Manifest {
				containerIds = append(containerIds, img.ContainerID)
			}
		}

		manifest.Status.AffectedPods[pod.Namespace+"/"+pod.Name] = containerIds
	}

	return manifest, nil
}

func sortedAffectedPodsKeys(manifest *secscanv1alpha1.ImageManifestVuln) []string {
	affectedPodsKeys := make([]string, 0, len(manifest.Status.AffectedPods))
	for k := range manifest.Status.AffectedPods {
		affectedPodsKeys = append(affectedPodsKeys, k)
	}
	sort.Strings(affectedPodsKeys)
	return affectedPodsKeys
}

func sortedPodKeysFromPods(pods []*corev1.Pod) []string {
	podKeys := make([]string, 0, len(pods))
	for _, pod := range pods {
		podKeys = append(podKeys, pod.Namespace+"/"+pod.Name)
	}
	return podKeys
}

func manifestNameFromImageID(imageID string) string {
	splitImageID := strings.SplitN(imageID, "@", 2)
	return strings.Replace(splitImageID[len(splitImageID)-1], ":", ".", 1)
}

type testClient struct {
	kclient       kubernetes.Interface
	iclient       icspclient.Interface
	sclient       secscanclient.Interface
	secscanClient *secscanfakes.FakeInterface
	podCount      map[string]int
}

func newTestClient() *testClient {
	return &testClient{
		kclient:       fake.NewSimpleClientset(),
		sclient:       fakesecscanclient.NewSimpleClientset(),
		iclient:       fakeicspclient.NewSimpleClientset(),
		secscanClient: &secscanfakes.FakeInterface{},
		podCount:      make(map[string]int),
	}
}

func generateNamespaceForTest(t *testing.T) string {
	prefix := strings.TrimPrefix(
		strings.ReplaceAll(
			strings.ToLower(t.Name()),
			"/",
			"-",
		),
		"test",
	)
	return prefix + "-" + strconv.FormatInt(time.Now().Unix(), 36)
}

func createTestPodsWithManifestForTest(t *testing.T, namespace string, c *testClient, n int, imageIDs []string, phase corev1.PodPhase) []*corev1.Pod {
	// Create some pods with an imageID
	testPods, err := c.createTestPods(namespace, n, imageIDs, corev1.PodRunning)
	if err != nil {
		t.Fatal(err)
	}

	// Create manifests for the Pod's images
	for _, imageID := range imageIDs {
		img, err := image.ParseImageID(imageID)
		if err != nil {
			t.Fatal(err)
		}

		_, err = c.createManifest(namespace, manifestName(img.Digest), testPods)
		if err != nil {
			t.Fatal(err)
		}
	}

	return testPods
}

func (c *testClient) podsClient(namespace string) v1.PodInterface {
	return c.kclient.CoreV1().Pods(namespace)
}

func (c *testClient) imageManifestVulnsClient(namespace string) secscanv1alpha1client.ImageManifestVulnInterface {
	return c.sclient.SecscanV1alpha1().ImageManifestVulns(namespace)
}

func (c *testClient) getPod(namespace, name string, getOptions metav1.GetOptions) (*corev1.Pod, error) {
	ctx := context.Background()
	return c.podsClient(namespace).Get(ctx, name, getOptions)
}

func (c *testClient) getManifest(namespace, name string, getOptions metav1.GetOptions) (*secscanv1alpha1.ImageManifestVuln, error) {
	ctx := context.Background()
	return c.imageManifestVulnsClient(namespace).Get(ctx, name, getOptions)
}

func (c *testClient) updateManifestStatus(manifest *secscanv1alpha1.ImageManifestVuln) (*secscanv1alpha1.ImageManifestVuln, error) {
	ctx := context.Background()
	man, err := c.imageManifestVulnsClient(manifest.ObjectMeta.Namespace).UpdateStatus(ctx, manifest, metav1.UpdateOptions{})
	time.Sleep(time.Second)
	return man, err
}

func (c *testClient) deletePod(namespace, name string, deleteOptions metav1.DeleteOptions) error {
	ctx := context.Background()
	err := c.podsClient(namespace).Delete(ctx, name, deleteOptions)
	time.Sleep(time.Second)
	return err
}

func (c *testClient) updatePodStatus(pod *corev1.Pod) (*corev1.Pod, error) {
	ctx := context.Background()
	return c.podsClient(pod.ObjectMeta.Namespace).UpdateStatus(ctx, pod, metav1.UpdateOptions{})
}

func (c *testClient) createPod(pod *corev1.Pod) (*corev1.Pod, error) {
	ctx := context.Background()
	res, err := c.podsClient(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	time.Sleep(time.Second)
	return res, err
}

func (c *testClient) createManifest(namespace, name string, pods []*corev1.Pod) (*secscanv1alpha1.ImageManifestVuln, error) {
	ctx := context.Background()
	manifest, err := generateManifest(namespace, name, pods)
	if err != nil {
		return nil, err
	}

	res, err := c.imageManifestVulnsClient(namespace).Create(ctx, manifest, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	return res, err
}

func (c *testClient) createTestPods(namespace string, n int, imageIDs []string, phase corev1.PodPhase) ([]*corev1.Pod, error) {
	results := []*corev1.Pod{}
	count := n + c.podCount[namespace]
	for i := c.podCount[namespace]; i < count; i++ {
		generatedPod, err := generatePod(namespace, "TestPod-"+strconv.Itoa(i), imageIDs, phase)
		if err != nil {
			return nil, err
		}

		p, err := c.createPod(generatedPod)
		if err != nil {
			return nil, err
		}
		c.podCount[namespace]++
		results = append(results, p)
	}
	return results, nil
}

func TestAddAffectedPod(t *testing.T) {
	ns := generateNamespaceForTest(t)
	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}

	c := newTestClient()

	// Create some test pods with their associated manifests
	testPods := createTestPodsWithManifestForTest(t, ns, c, 1, []string{imageIDs[0]}, corev1.PodRunning)
	pod := testPods[0]
	manifest, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Adding existing key
	podKey := pod.Namespace + "/" + pod.Name
	manifest, changed := addAffectedPod(podKey, pod.Status.ContainerStatuses[0].ContainerID, manifest)
	assert.False(t, changed)

	// Adding new containerID under same pod
	manifest, changed = addAffectedPod(podKey, "docker://"+randString(64), manifest)
	assert.True(t, changed)
	assert.Len(t, manifest.Status.AffectedPods, 1)
	assert.Len(t, manifest.Status.AffectedPods[podKey], 2)

	// Adding new containerID under different pod
	manifest, changed = addAffectedPod(ns+"/"+"someotherpod", "docker://"+randString(64), manifest)
	assert.True(t, changed)
	assert.Len(t, manifest.Status.AffectedPods, 2)
}

func TestRemoveDanglingPods(t *testing.T) {
	ns := generateNamespaceForTest(t)
	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	expectedManifestName := "sha256.94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"

	c := newTestClient()

	// Create some test pods with their associated manifests
	testPods := createTestPodsWithManifestForTest(t, ns, c, 4, []string{testImageID}, corev1.PodRunning)
	manifest, err := c.getManifest(ns, expectedManifestName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Try removing some pods from affectedPods
	validPodKeys := []string{
		testPods[0].Namespace + "/" + testPods[0].Name,
		testPods[1].Namespace + "/" + testPods[1].Name,
	}
	manifest, changed := removeDanglingPods(validPodKeys, manifest)
	sort.Strings(validPodKeys)
	assert.True(t, changed)
	assert.Len(t, manifest.Status.AffectedPods, 2)
	assert.Equal(t, validPodKeys, sortedAffectedPodsKeys(manifest))

	// When there are no dangling pod references in affectedPods, changed should be false
	manifest, changed = removeDanglingPods(validPodKeys, manifest)
	assert.False(t, changed)
	assert.Len(t, manifest.Status.AffectedPods, 2)
	assert.Equal(t, validPodKeys, sortedAffectedPodsKeys(manifest))
}

func TestGarbageCollectManifestNoDeletion(t *testing.T) {
	ctx := context.Background()
	ns := generateNamespaceForTest(t)
	testImageID1 := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	testImageID2 := "quay.io/test/nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a"
	imageIDs := []string{testImageID1, testImageID2}

	c := newTestClient()

	// Create some test pods with their associated manifests
	testPods1 := createTestPodsWithManifestForTest(t, ns, c, 4, []string{imageIDs[0]}, corev1.PodRunning)

	// Create some other test pods (different imageID) with their associated manifests
	testPods2 := createTestPodsWithManifestForTest(t, ns, c, 4, []string{imageIDs[1]}, corev1.PodRunning)

	// Garbage collecting manifest with affected pods should not delete anything
	err := garbageCollectManifests(ctx, c.podsClient(ns), c.imageManifestVulnsClient(ns))
	if err != nil {
		t.Fatal(err)
	}

	// Check that the number of manifests if the same
	manifestList, err := c.imageManifestVulnsClient(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifests := manifestList.Items
	assert.Len(t, manifests, 2)

	// Check that the affectedPods are the same
	manifest1, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[0]), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, sortedPodKeysFromPods(testPods1), sortedAffectedPodsKeys(manifest1))

	manifest2, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[1]), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, sortedPodKeysFromPods(testPods2), sortedAffectedPodsKeys(manifest2))
}

func TestGarbageCollectManifestDeletion(t *testing.T) {
	ctx := context.Background()
	ns := generateNamespaceForTest(t)
	testImageID1 := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	testImageID2 := "quay.io/test/nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a"
	imageIDs := []string{testImageID1, testImageID2}

	c := newTestClient()

	// Create some test pods with their associated manifests
	testPods := createTestPodsWithManifestForTest(t, ns, c, 4, []string{imageIDs[0]}, corev1.PodRunning)

	// Create some other test pods (different imageID) with their associated manifests to be removed
	createTestPodsWithManifestForTest(t, ns, c, 4, []string{imageIDs[1]}, corev1.PodRunning)

	// Remove the second set of pods from their manifest
	manifestToDelete, err := c.getManifest(ns, manifestNameFromImageID(imageIDs[1]), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	validPodKeys := []string{}
	manifestToDelete, changed := removeDanglingPods(validPodKeys, manifestToDelete)
	manifestToDelete, err = c.updateManifestStatus(manifestToDelete)

	assert.NoError(t, err)
	assert.True(t, changed)
	assert.Empty(t, manifestToDelete.Status.AffectedPods)

	// Garbage collect empty manifest
	assert.NoError(t, garbageCollectManifests(ctx, c.podsClient(ns), c.imageManifestVulnsClient(ns)))
	manifestList, err := c.imageManifestVulnsClient(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifests := manifestList.Items
	assert.Len(t, manifests, 1)
	assert.Equal(t, manifests[0].Name, manifestNameFromImageID(imageIDs[0]))
	assert.Equal(t, sortedPodKeysFromPods(testPods), sortedAffectedPodsKeys(manifests[0]))
}

func TestGarbageCollectManifestDanglingPods(t *testing.T) {
	ctx := context.Background()
	ns := generateNamespaceForTest(t)
	testImageID := "quay.io/test/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"
	imageIDs := []string{testImageID}

	c := newTestClient()

	// Create some test pods with their associated manifests
	testPods := createTestPodsWithManifestForTest(t, ns, c, 4, []string{imageIDs[0]}, corev1.PodRunning)

	// Delete some pods
	err := c.deletePod(testPods[0].Namespace, testPods[0].Name, metav1.DeleteOptions{})
	assert.NoError(t, err)
	err = c.deletePod(testPods[1].Namespace, testPods[1].Name, metav1.DeleteOptions{})
	assert.NoError(t, err)
	testPods = testPods[2:]

	err = garbageCollectManifests(ctx, c.podsClient(ns), c.imageManifestVulnsClient(ns))
	manifestList, err := c.imageManifestVulnsClient(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifests := manifestList.Items
	assert.Len(t, manifests, 1)
	assert.Len(t, manifests[0].Status.AffectedPods, 2)
	assert.Equal(t, sortedPodKeysFromPods(testPods), sortedAffectedPodsKeys(manifests[0]))
}
