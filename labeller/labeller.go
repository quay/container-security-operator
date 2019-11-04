package labeller

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	secscanv1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	secscanclient "github.com/quay/container-security-operator/generated/versioned"
	"github.com/quay/container-security-operator/image"
	"github.com/quay/container-security-operator/k8sutils"
	"github.com/quay/container-security-operator/prometheus"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/quay"

	log "github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

var (
	highestLabel  = "highest"
	FixablesLabel = "fixables"

	UnknownLabel    = "Unknown"
	NegligibleLabel = "Negligible"
	LowLabel        = "Low"
	MediumLabel     = "Medium"
	HighLabel       = "High"
	CriticalLabel   = "Critical"
	Defcon1Label    = "Defcon1"

	lastScanAnnotation   = "lastScan"
	imageVulnsAnnotation = "imageVulns"
)

type Labeller struct {
	kclient       kubernetes.Interface
	sclient       secscanclient.Interface
	secscanClient secscan.Client
	logger        log.Logger
	namespaces    []string

	queue                     workqueue.RateLimitingInterface
	podInformer               cache.SharedIndexInformer
	imageManifestVulnInformer cache.SharedIndexInformer

	labelPrefix  string
	resyncPeriod time.Duration

	prometheus *prometheus.Server

	vulnerabilities *lockableVulnerabilities
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

	sclient, err := secscanclient.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	scannerUrl, err := url.Parse(config.SecurityScanner.Host)
	if err != nil {
		return nil, err
	}

	var secscanClient secscan.Client
	secscanClient, err = quay.NewQuayClient(
		scannerUrl,
		config.SecurityScanner.Token,
		config.SecurityScanner.APIVersion,
	)
	if err != nil {
		return nil, err
	}

	if !secscanClient.Ping() {
		return nil, fmt.Errorf("Could not reach security scanning service: %s", scannerUrl)
	}

	l := &Labeller{
		kclient:         kclient,
		sclient:         sclient,
		secscanClient:   secscanClient,
		logger:          logger,
		namespaces:      config.Namespaces[:],
		labelPrefix:     config.LabelPrefix,
		resyncPeriod:    config.Interval,
		prometheus:      prometheus.NewServer(config.PrometheusAddr),
		vulnerabilities: NewLockableVulnerabilites(),
	}

	l.namespaces = config.Namespaces[:]
	l.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "labeller")

	multiNamespacePodListWatcher := NewMultiNamespaceListerWatcher(
		kclient.CoreV1().RESTClient(),
		"pods",
		l.namespaces,
		fields.Everything(),
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
		l.sclient.SecscanV1alpha1().RESTClient(),
		"imagemanifestvulns",
		l.namespaces,
		fields.Everything(),
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
	// Will block until there is an item to process
	key, quit := l.queue.Get()
	if quit {
		level.Error(l.logger).Log("msg", "Failed to get from queue")
		return false
	}
	defer l.queue.Done(key)

	err := l.SecurityLabelPod(key.(string))
	if err == nil {
		l.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Failed with : %w", key, err))
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
	}
}

func (l *Labeller) handleAddImageManifestVuln(obj interface{}) {
	imgmanifestvuln := obj.(*secscanv1alpha1.ImageManifestVuln)
	if key, ok := l.keyFunc(imgmanifestvuln); ok {
		// Nothing to do. ImageManifestVulns should be treated as just data
		level.Debug(l.logger).Log("msg", "ImageManifestVuln added", "key", key)
	}
}

func (l *Labeller) handleDeleteImageManifestVuln(obj interface{}) {
	imgmanifestvuln := obj.(*secscanv1alpha1.ImageManifestVuln)
	if key, ok := l.keyFunc(imgmanifestvuln); ok {
		// Nothing to do. ImageManifestVulns should be treated as just data
		level.Debug(l.logger).Log("msg", "ImageManifestVuln deleted", "key", key)
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

func (l *Labeller) SecurityLabelPod(key string) error {
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
		if err := removeAffectedPodFromManifests(imageManifestVulnClient, key); err != nil {
			return err
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
	if err := garbageCollectManifests(podClient, imageManifestVulnClient); err != nil {
		level.Error(l.logger).Log("msg", "Failed to garbage collect unreferenced ImageManifestVulns", "err", err)
		return fmt.Errorf("Failed to garbage collect unreferenced ImageManifestVulns: %w", err)
	}

	// Get pull secrets, if any
	pullSecretRefs := pod.Spec.ImagePullSecrets
	dockerJsonConfig, err := image.ParsePullSecrets(secretClient, pullSecretRefs)
	if err != nil {
		return err
	}

	// Add pod containers' images to scan
	imagesToScan := make(map[string]*image.Image)
	for _, containerStatus := range pod.Status.ContainerStatuses {
		image, err := image.ParseContainerStatus(containerStatus)
		if err != nil {
			level.Error(l.logger).Log("msg", "Error parsing imageID", "imageID", containerStatus.ImageID)
			continue
		}
		if val, ok := dockerJsonConfig.Auths[image.Host]; ok {
			image.Auth = val.Auth
		}
		image.ContainerName = containerStatus.Name
		imagesToScan[image.Digest] = image
	}

	for _, img := range imagesToScan {
		var imgManifestVuln *secscanv1alpha1.ImageManifestVuln
		manifestKey := fmt.Sprintf("%s/%s", pod.Namespace, manifestName(img.Digest))

		obj, exists, err = l.imageManifestVulnInformer.GetIndexer().GetByKey(manifestKey)
		if err != nil {
			continue
		}

		if !exists {
			layerData, err := l.secscanClient.GetLayerData(img, true, true)
			if err != nil {
				level.Error(l.logger).Log("msg", "Error getting image's manifest data", "key", key, "err", err)
				continue
			}

			imageName := strings.Split(img.String(), ":")[0]
			imgManifestVuln, err := buildImageManifestVuln(pod.Namespace, imageName, img.Digest, layerData)
			if err != nil {
				level.Error(l.logger).Log("msg", "Error building ImageManifestVuln", "manifestKey", manifestKey, "key", key, "err", err)
				continue
			}

			if len(imgManifestVuln.Spec.Features) == 0 {
				continue
			}

			imgManifestVuln, _ = addAffectedPod(key, img.ContainerID, imgManifestVuln)

			createdVuln, err := imageManifestVulnClient.Create(imgManifestVuln)
			if err != nil {
				level.Error(l.logger).Log("msg", "Error creating ImageManifestVuln", "manifestKey", manifestKey, "key", key, "err", err)
				continue
			}

			level.Info(l.logger).Log("msg", "Created ImageManifestVuln", "manifestKey", manifestKey, "key", key)
			createdVuln.Status = imgManifestVuln.Status
			if _, err = imageManifestVulnClient.UpdateStatus(createdVuln); err != nil {
				level.Error(l.logger).Log("msg", "Error updating ImageManifestVuln status", "manifestKey", manifestKey, "key", key, "err", err)
			}
			continue
		}

		imgManifestVuln = obj.(*secscanv1alpha1.ImageManifestVuln)
		imgManifestVuln, _ = addAffectedPod(key, img.ContainerID, imgManifestVuln)

		updatedVuln, err := imageManifestVulnClient.Update(imgManifestVuln)
		if err != nil {
			level.Error(l.logger).Log("msg", "Error updating ImageManifestVuln", "key", manifestKey, "err", err)
		}
		updatedVuln.Status = imgManifestVuln.Status
		if _, err := imageManifestVulnClient.UpdateStatus(updatedVuln); err != nil {
			level.Error(l.logger).Log("msg", "Error updating ImageManifestVuln status", "key", manifestKey, "err", err)
			continue
		}
	}

	// Populate prometheus metrics
	l.promPopulateVulnsCount()

	return nil
}

func (l *Labeller) promPopulateVulnsCount() {
	podVulns := l.vulnerabilities.countTotalVulnerabilities()
	prometheus.PromVulnCount.WithLabelValues(UnknownLabel).Set(float64(podVulns.Unknown))
	prometheus.PromVulnCount.WithLabelValues(NegligibleLabel).Set(float64(podVulns.Negligible))
	prometheus.PromVulnCount.WithLabelValues(LowLabel).Set(float64(podVulns.Low))
	prometheus.PromVulnCount.WithLabelValues(MediumLabel).Set(float64(podVulns.Medium))
	prometheus.PromVulnCount.WithLabelValues(HighLabel).Set(float64(podVulns.High))
	prometheus.PromVulnCount.WithLabelValues(CriticalLabel).Set(float64(podVulns.Critical))
	prometheus.PromVulnCount.WithLabelValues(Defcon1Label).Set(float64(podVulns.Defcon1))
}

func (l *Labeller) getLabelKey(keyname string) string {
	return strings.Join([]string{l.labelPrefix, keyname}, "/")
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
