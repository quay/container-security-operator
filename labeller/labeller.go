package labeller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	icspclient "github.com/openshift/client-go/operator/clientset/versioned"
	secscanv1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	secscanclient "github.com/quay/container-security-operator/generated/clientset/versioned"
	secscanv1alpha1client "github.com/quay/container-security-operator/generated/clientset/versioned/typed/secscan/v1alpha1"
	"github.com/quay/container-security-operator/image"
	"github.com/quay/container-security-operator/k8sutils"
	"github.com/quay/container-security-operator/prometheus"
	"github.com/quay/container-security-operator/secscan"

	log "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var (
	UnknownLabel    = "Unknown"
	NegligibleLabel = "Negligible"
	LowLabel        = "Low"
	MediumLabel     = "Medium"
	HighLabel       = "High"
	CriticalLabel   = "Critical"
	Defcon1Label    = "Defcon1"
)

type Labeller struct {
	kclient           kubernetes.Interface
	sclient           secscanclient.Interface
	iclient           icspclient.Interface
	secscanClient     secscan.Interface
	wellKnownEndpoint string
	logger            log.Logger
	namespaces        []string

	queue                     workqueue.RateLimitingInterface
	podInformer               cache.SharedIndexInformer
	imageManifestVulnInformer cache.SharedIndexInformer

	labelPrefix     string
	resyncPeriod    time.Duration
	resyncThreshold time.Duration

	prometheus *prometheus.Server
}

func New(config *Config, kubeconfig string, logger log.Logger) (*Labeller, error) {
	cfg, err := k8sutils.NewClusterConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	kclient, err := k8sutils.LoadClientset(cfg)
	if err != nil {
		return nil, err
	}

	iclient, err := icspclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	sclient, err := secscanclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	var secscanClient secscan.Interface
	secscanClient, err = secscan.NewClient()
	if err != nil {
		return nil, err
	}

	l := &Labeller{
		kclient:           kclient,
		sclient:           sclient,
		iclient:           iclient,
		secscanClient:     secscanClient,
		logger:            logger,
		namespaces:        config.Namespaces[:],
		labelPrefix:       config.LabelPrefix,
		resyncPeriod:      config.Interval,
		resyncThreshold:   config.ResyncThreshold,
		wellKnownEndpoint: config.WellknownEndpoint,
		prometheus:        prometheus.NewServer(config.PrometheusAddr),
	}

	l.namespaces = config.Namespaces[:]
	l.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "labeller")

	multiNamespacePodListWatcher := NewMultiNamespaceListerWatcher(
		l.namespaces,
		func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					ctx := context.Background()
					return l.kclient.CoreV1().Pods(namespace).List(ctx, options)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					ctx := context.Background()
					return l.kclient.CoreV1().Pods(namespace).Watch(ctx, opts)
				},
			}
		},
	)
	l.podInformer = cache.NewSharedIndexInformer(
		multiNamespacePodListWatcher,
		&corev1.Pod{},
		l.resyncPeriod,
		cache.Indexers{},
	)
	l.podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    l.handleAddPod,
		DeleteFunc: l.handleDeletePod,
		UpdateFunc: l.handleUpdatePod,
	})

	multiNamespaceImageManifestVulnListWatcher := NewMultiNamespaceListerWatcher(
		l.namespaces,
		func(namespace string) cache.ListerWatcher {
			return &cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					ctx := context.Background()
					return l.sclient.SecscanV1alpha1().ImageManifestVulns(namespace).List(ctx, options)
				},
				WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
					ctx := context.Background()
					return l.sclient.SecscanV1alpha1().ImageManifestVulns(namespace).Watch(ctx, opts)
				},
			}
		},
	)
	l.imageManifestVulnInformer = cache.NewSharedIndexInformer(
		multiNamespaceImageManifestVulnListWatcher,
		&secscanv1alpha1.ImageManifestVuln{},
		l.resyncPeriod,
		cache.Indexers{},
	)
	l.imageManifestVulnInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    l.handleAddImageManifestVuln,
		DeleteFunc: l.handleDeleteImageManifestVuln,
		UpdateFunc: l.handleUpdateImageManifestVuln,
	})

	return l, nil
}

func (l *Labeller) Run(stopc <-chan struct{}) error {
	defer l.queue.ShutDown()

	l.prometheus.Start()
	level.Info(l.logger).Log("msg", "Started prometheus server")

	go l.podInformer.Run(stopc)
	go l.imageManifestVulnInformer.Run(stopc)
	if err := l.waitForCacheSync(stopc); err != nil {
		return err
	}

	go l.worker()
	level.Info(l.logger).Log("msg", "Started labeller worker")

	// Blocks until an interrupt is received
	<-stopc
	level.Info(l.logger).Log("msg", "Stopping labeller...")
	<-l.prometheus.Stop()
	level.Info(l.logger).Log("msg", "Stopping prometheus...")
	return nil
}

func (l *Labeller) worker() {
	for l.processNextItem() {
	}
}

func (l *Labeller) processNextItem() bool {
	prometheus.PromQueueSize.Set(float64(l.queue.Len()))

	// Will block until there is an item to process
	key, quit := l.queue.Get()
	if quit {
		level.Error(l.logger).Log("msg", "Failed to get from queue")
		return false
	}
	defer l.queue.Done(key)

	err := l.Reconcile(context.Background(), key.(string))
	if err == nil {
		l.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%s failed with : %w", key, err))
	l.queue.AddRateLimited(key)
	level.Info(l.logger).Log("msg", "Requeued item", "key", key.(string))

	return true
}

func (l *Labeller) keyFunc(obj interface{}) (string, bool) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		level.Error(l.logger).Log("msg", "Failed to create object key", "err", err)
		return key, false
	}
	return key, true
}

func (l *Labeller) handleAddPod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	if !l.podInNamespaces(pod) {
		return
	}

	if key, ok := l.keyFunc(pod); ok {
		l.queue.Add(key)
		level.Debug(l.logger).Log("msg", "Pod added", "key", key)
		prometheus.PromPodEventsTotal.WithLabelValues("add", pod.Namespace).Inc()
	}
}

func (l *Labeller) handleDeletePod(obj interface{}) {
	pod := obj.(*corev1.Pod)
	if !l.podInNamespaces(pod) {
		return
	}

	if key, ok := l.keyFunc(pod); ok {
		l.queue.Add(key)
		level.Debug(l.logger).Log("msg", "Pod deleted", "key", key)
		prometheus.PromPodEventsTotal.WithLabelValues("delete", pod.Namespace).Inc()
	}
}

func (l *Labeller) handleUpdatePod(oldObj, newObj interface{}) {
	newPod := newObj.(*corev1.Pod)

	if !l.podInNamespaces(newPod) {
		return
	}

	if key, ok := l.keyFunc(newPod); ok {
		l.queue.Add(key)
		level.Debug(l.logger).Log("msg", "Pod updated", "key", key)
		prometheus.PromPodEventsTotal.WithLabelValues("update", newPod.Namespace).Inc()
	}
}

func (l *Labeller) handleAddImageManifestVuln(obj interface{}) {
	imgmanifestvuln := obj.(*secscanv1alpha1.ImageManifestVuln)
	if key, ok := l.keyFunc(imgmanifestvuln); ok {
		// Nothing to do. ImageManifestVulns should be treated as just data
		level.Debug(l.logger).Log("msg", "ImageManifestVuln added", "key", key)
		prometheus.PromImageManifestVulnEventsTotal.WithLabelValues("add", imgmanifestvuln.Namespace).Inc()
	}
}

func (l *Labeller) handleDeleteImageManifestVuln(obj interface{}) {
	imgmanifestvuln := obj.(*secscanv1alpha1.ImageManifestVuln)
	if key, ok := l.keyFunc(imgmanifestvuln); ok {
		// Nothing to do. ImageManifestVulns should be treated as just data
		level.Debug(l.logger).Log("msg", "ImageManifestVuln deleted", "key", key)
		prometheus.PromImageManifestVulnEventsTotal.WithLabelValues("delete", imgmanifestvuln.Namespace).Inc()
	}
}

func (l *Labeller) handleUpdateImageManifestVuln(oldObj, newObj interface{}) {
	if oldObj.(*secscanv1alpha1.ImageManifestVuln).ResourceVersion == newObj.(*secscanv1alpha1.ImageManifestVuln).ResourceVersion {
		return
	}

	imgmanifestvuln := newObj.(*secscanv1alpha1.ImageManifestVuln)
	if key, ok := l.keyFunc(imgmanifestvuln); ok {
		// Nothing to do. ImageManifestVulns should be treated as just data
		level.Debug(l.logger).Log("msg", "ImageManifestVuln updated", "key", key)
		prometheus.PromImageManifestVulnEventsTotal.WithLabelValues("update", imgmanifestvuln.Namespace).Inc()
	}
}

func (l *Labeller) waitForCacheSync(stopc <-chan struct{}) error {
	ok := true
	informers := []struct {
		name     string
		informer cache.SharedIndexInformer
	}{
		{"Pod", l.podInformer},
		{"ImageManifestVuln", l.imageManifestVulnInformer},
	}
	for _, inf := range informers {
		if !cache.WaitForCacheSync(stopc, inf.informer.HasSynced) {
			level.Error(l.logger).Log("msg", fmt.Sprintf("failed to sync %s cache", inf.name))
			ok = false
		} else {
			level.Debug(l.logger).Log("msg", fmt.Sprintf("successfully synced %s cache", inf.name))
		}
	}
	if !ok {
		return errors.New("failed to sync caches")
	}
	level.Info(l.logger).Log("msg", "successfully synced all caches")
	return nil
}

func (l *Labeller) sync(img *image.Image) (*secscan.Layer, error) {
	defer prometheus.ObserveSecscanRequestDuration(img.Host)()

	wellknownClient, err := l.secscanClient.Wellknown(img.Host, l.wellKnownEndpoint)
	if err != nil {
		return nil, err
	}

	manifestSecurityTemplate, err := wellknownClient.ManifestSecurityTemplate()
	if err != nil {
		return nil, err
	}

	layerData, err := l.secscanClient.GetLayerDataFromTemplate(manifestSecurityTemplate, img, true, true)
	prometheus.PromSecscanRequestsTotal.WithLabelValues(img.Host).Inc()
	if err != nil {
		return nil, err
	}

	return layerData, nil
}

// MirroredImages checks if there is a mirror configuration for the provided image. Returns a list
// of configured mirrors or an empty slice if no mirror was found.
func (l *Labeller) MirroredImages(img *image.Image, mirrors map[string][]string) []*image.Image {
	imgs := make([]*image.Image, 0)
	if _, ok := mirrors[img.Host]; ok {
		for _, mirror := range mirrors[img.Host] {
			imgcopy := *img
			imgcopy.ApplyMirror(mirror)
			imgs = append(imgs, &imgcopy)
		}
	}

	hostAndNS := fmt.Sprintf("%s/%s", img.Host, img.Namespace)
	if _, ok := mirrors[hostAndNS]; !ok {
		return imgs
	}

	for _, mirror := range mirrors[hostAndNS] {
		imgcopy := *img
		imgcopy.ApplyMirror(mirror)
		imgs = append(imgs, &imgcopy)
	}

	return imgs
}

func (l *Labeller) scan(ctx context.Context, pod *corev1.Pod, img *image.Image, key string) error {
	var imgManifestVuln *secscanv1alpha1.ImageManifestVuln
	imageManifestVulnClient := l.sclient.SecscanV1alpha1().ImageManifestVulns(pod.Namespace)
	manifestKey := fmt.Sprintf("%s/%s", pod.Namespace, manifestName(img.Digest))

	obj, exists, err := l.imageManifestVulnInformer.GetIndexer().GetByKey(manifestKey)
	if err != nil {
		return fmt.Errorf("unable to get image manifest vuln: %w", err)
	}

	if !exists {
		layerData, err := l.sync(img)
		if err != nil {
			return fmt.Errorf("failed to sync layer data: %w", err)
		}

		imageName := strings.Split(img.String(), ":")[0]
		imgManifestVuln, err := buildImageManifestVuln(pod.Namespace, imageName, img.Digest, layerData)
		if err != nil {
			return fmt.Errorf("error building image manifest vuln: %w", err)
		}

		if len(imgManifestVuln.Spec.Features) == 0 {
			level.Info(l.logger).Log("msg", "no spec.features", "image", img.String())
			return nil
		}

		imgManifestVuln, _ = addAffectedPod(key, img.ContainerID, imgManifestVuln)

		createdVuln, err := imageManifestVulnClient.Create(ctx, imgManifestVuln, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("error creating image manifest vuln: %w", err)
		}

		level.Info(l.logger).Log("msg", "Created ImageManifestVuln", "manifestKey", manifestKey, "key", key)
		createdVuln.Status = imgManifestVuln.Status
		if _, err = imageManifestVulnClient.UpdateStatus(ctx, createdVuln, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("error updating image manifest vuln: %w", err)
		}

		level.Info(l.logger).Log("msg", "image manifest vuln creted", "image", img.String())
		return nil
	}

	imgManifestVuln = obj.(*secscanv1alpha1.ImageManifestVuln)

	// Check if the spec needs to be resynced
	lastUpdateTime, err := lastManfestUpdateTime(imgManifestVuln)
	if err != nil {
		return fmt.Errorf("failed to parse image manifest vuln: %w", err)
	}

	if time.Now().UTC().Sub(*lastUpdateTime) > l.resyncThreshold {
		level.Info(l.logger).Log("msg", "Resyncing ImageManifestVuln", manifestKey, "key", key, "err", err)
		layerData, err := l.sync(img)
		if err != nil {
			return fmt.Errorf("failed to resync layer data: %w", err)
		}

		imgManifestVuln, err = updateImageManifestVulnSpec(imgManifestVuln, layerData)
		if err != nil {
			return fmt.Errorf("faile to update image manifest vuln spec: %w", err)
		}

		imgManifestVuln = updateImageManifestVulnLastUpdate(imgManifestVuln)
	}

	imgManifestVuln, _ = addAffectedPod(key, img.ContainerID, imgManifestVuln)

	updatedVuln, err := imageManifestVulnClient.Update(ctx, imgManifestVuln, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating image manifest vuln: %w", err)
	}

	updatedVuln.Status = imgManifestVuln.Status
	if _, err := imageManifestVulnClient.UpdateStatus(ctx, updatedVuln, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating image manifest vuln status: %w", err)
	}

	return nil
}

func (l *Labeller) Reconcile(ctx context.Context, key string) error {
	defer prometheus.ObserveReconciliationDuration()()

	ns := strings.Split(key, "/")[0]
	podClient := l.kclient.CoreV1().Pods(ns)
	secretClient := l.kclient.CoreV1().Secrets(ns)
	imageManifestVulnClient := l.sclient.SecscanV1alpha1().ImageManifestVulns(ns)

	obj, exists, err := l.podInformer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		// Remove pod references from existing imagemanifestvulns.
		level.Info(l.logger).Log("msg", "Removing deleted pod from ImageManifestVulns", "key", key)
		if err := removeAffectedPodFromManifests(ctx, imageManifestVulnClient, key); err != nil {
			level.Error(l.logger).Log("msg", "Failed to remove deleted pod from ImageManifestVulns", "err", err, "key", key)
			return err
		}

		// Garbage collect unreferenced manifests and remove dangling pods from existing manifests
		level.Info(l.logger).Log("msg", "Garbage collecting unreferenced ImageManifestVulns", "key", key)
		if err := garbageCollectManifests(ctx, podClient, imageManifestVulnClient); err != nil {
			level.Error(l.logger).Log("msg", "Failed to garbage collect unreferenced ImageManifestVulns", "err", err, "key", key)
			return fmt.Errorf("Failed to garbage collect unreferenced ImageManifestVulns: %w", err)
		}

		return nil
	}

	pod := obj.(*corev1.Pod)

	// Reenqueue pod if not ready and running
	if podReadyRunning, err := k8sutils.PodRunningAndReady(pod); !podReadyRunning {
		if err != nil {
			return err
		}
		return fmt.Errorf("Pod not running or ready")
	}

	// Garbage collect unreferenced manifests and remove dangling pods from existing manifests
	level.Info(l.logger).Log("msg", "Garbage collecting unreferenced ImageManifestVulns", "key", key)
	if err := garbageCollectManifests(ctx, podClient, imageManifestVulnClient); err != nil {
		level.Error(l.logger).Log("msg", "Failed to garbage collect unreferenced ImageManifestVulns", "err", err)
		return fmt.Errorf("Failed to garbage collect unreferenced ImageManifestVulns: %w", err)
	}

	// Get pull secrets, if any
	pullSecretRefs := pod.Spec.ImagePullSecrets
	dockerJsonConfig, err := image.ParsePullSecrets(ctx, secretClient, pullSecretRefs)
	if err != nil {
		return err
	}

	defaultSecretClient := l.kclient.CoreV1().Secrets("openshift-config")
	clusterAuths, err := image.ParsePullSecret(ctx, defaultSecretClient, "pull-secret")
	if err != nil {
		level.Error(l.logger).Log("msg", "fail to process global pull secret", "err", err)
		clusterAuths = &image.DockerConfigJson{Auths: map[string]image.DockerAuth{}}
	}

	icsps, err := l.iclient.OperatorV1alpha1().ImageContentSourcePolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	mirrors := map[string][]string{}
	for _, icsp := range icsps.Items {
		for _, mirror := range icsp.Spec.RepositoryDigestMirrors {
			mirrors[mirror.Source] = append(mirrors[mirror.Source], mirror.Mirrors...)
		}
	}

	// Add pod containers' images to scan
	imagesToScan := make(map[string][]*image.Image)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		img, err := image.ParseContainerStatus(containerStatus)
		if err != nil {
			level.Error(l.logger).Log("msg", "Error parsing imageID", "imageID", containerStatus.ImageID)
			continue
		}

		img.ContainerName = containerStatus.Name
		images := l.MirroredImages(img, mirrors)
		images = append(images, img)

		for _, i := range images {
			if val, ok := dockerJsonConfig.Auths[i.Host]; ok {
				i.Auth = val.Auth
			} else if val, ok := clusterAuths.Auths[i.Host]; ok {
				i.Auth = val.Auth
			}
		}

		imagesToScan[img.Digest] = append(imagesToScan[img.Digest], images...)
	}

	for _, imgs := range imagesToScan {
		for _, img := range imgs {
			level.Info(l.logger).Log("msg", "scanning", "image", img.String())
			if err := l.scan(ctx, pod, img, key); err != nil {
				level.Error(l.logger).Log("msg", "error scanning", "err", err)
				continue
			}
			break
		}
	}

	// Populate prometheus metrics
	l.promPopulateVulnsCount(ctx, imageManifestVulnClient)

	return nil
}

func (l *Labeller) promPopulateVulnsCount(ctx context.Context, manifestclient secscanv1alpha1client.ImageManifestVulnInterface) {
	podVulns, images, err := aggVulnerabilityCount(ctx, manifestclient)
	if err != nil {
		level.Warn(l.logger).Log("msg", "Failed to update aggregate vulnerabilities metrics", "err", err)
		return
	}
	prometheus.PromVulnerableImages.Set(float64(images))
	prometheus.PromVulnCount.WithLabelValues(UnknownLabel).Set(float64(podVulns.Unknown))
	prometheus.PromVulnCount.WithLabelValues(NegligibleLabel).Set(float64(podVulns.Negligible))
	prometheus.PromVulnCount.WithLabelValues(LowLabel).Set(float64(podVulns.Low))
	prometheus.PromVulnCount.WithLabelValues(MediumLabel).Set(float64(podVulns.Medium))
	prometheus.PromVulnCount.WithLabelValues(HighLabel).Set(float64(podVulns.High))
	prometheus.PromVulnCount.WithLabelValues(CriticalLabel).Set(float64(podVulns.Critical))
	prometheus.PromVulnCount.WithLabelValues(Defcon1Label).Set(float64(podVulns.Defcon1))
}

func (l *Labeller) podInNamespaces(pod *corev1.Pod) bool {
	if len(l.namespaces) == 0 {
		return true
	}
	for _, ns := range l.namespaces {
		if pod.ObjectMeta.Namespace == ns {
			return true
		}
	}
	return false
}
