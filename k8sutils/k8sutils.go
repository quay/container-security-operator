package k8sutils

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	// Uncomment depending on auth provider
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#syntax-and-character-set
	validLabelKeyNameRegex = "^([A-Za-z0-9]+[-_\\.]?)*[A-Za-z0-9]$"
	validLabelValueRegex   = "^([A-Za-z0-9]+[-_\\.]?)*[A-Za-z0-9]$|^$"

	// RFC 1123
	validHostnameRegex = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$"

	defaultQPS   = 100
	defaultBurst = 100
)

var (
	ErrInvalidLabelKeyHostnameLength = errors.New("k8sutils: Invalid label key hostname length")
	ErrInvalidLabelKeyNameLength     = errors.New("k8sutils: Invalid label key name length")
	ErrInvalidLabelValueLength       = errors.New("k8sutils: Invalid label value length")

	TPRPollInterval = 3 * time.Second
	TPRPollTimeout  = 30 * time.Second
)

func NewClusterConfig(kubeconfig string) (*rest.Config, error) {
	var cfg *rest.Config
	var err error

	if len(kubeconfig) == 0 {
		if cfg, err = rest.InClusterConfig(); err != nil {
			return nil, err
		}
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}
	cfg.QPS = defaultQPS
	cfg.Burst = defaultBurst

	return cfg, nil
}

func LoadInClusterConfig() (*rest.Config, error) {
	var cfg *rest.Config
	var err error

	cfg, err = rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func LoadClientset(cfg *rest.Config) (*kubernetes.Clientset, error) {
	var clientset *kubernetes.Clientset
	var err error

	clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

func ListPods(pclient clientv1.PodInterface) (*v1.PodList, error) {
	pods, err := pclient.List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return pods, nil
}

func UpdatePod(pclient clientv1.PodInterface, pod *v1.Pod) error {
	p, err := pclient.Get(pod.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	pod.ResourceVersion = p.ResourceVersion
	_, err = pclient.Update(pod)
	if err != nil {
		return err
	}

	return nil
}

func PodRunningAndReady(pod *v1.Pod) (bool, error) {
	switch pod.Status.Phase {
	case v1.PodFailed, v1.PodSucceeded, v1.PodUnknown, v1.PodPending:
		return false, fmt.Errorf("Pod phase not running: %s", pod.Status.Phase)
	case v1.PodRunning:
		for _, cond := range pod.Status.Conditions {
			if cond.Type != v1.PodReady {
				continue
			}
			return cond.Status == v1.ConditionTrue, nil
		}
		return false, fmt.Errorf("Pod condition not ready")
	}
	return false, nil
}

func PodAddOrUpdateLabel(pod *v1.Pod, key, value string) error {
	if valid, err := ValidLabelKey(key); !valid {
		return err
	}
	if valid, err := ValidLabelValue(value); !valid {
		return err
	}
	pod.ObjectMeta.Labels[key] = value
	return nil
}

func PodAddOrUpdateLabels(pod *v1.Pod, labels map[string]string) {
	for k, v := range labels {
		err := PodAddOrUpdateLabel(pod, k, v)
		if err != nil {
			log.WithFields(log.Fields{
				"msg":       err,
				"name":      pod.ObjectMeta.Name,
				"namespace": pod.ObjectMeta.Namespace,
				"phase":     pod.Status.Phase,
			}).Error("Error adding label to pod.")
		}
	}
}

func ValidLabelKey(key string) (bool, error) {
	// Optional DNS hostname and label key name are separated by "/"
	fullKey := strings.Split(key, "/")
	if len(fullKey) > 2 {
		return false, fmt.Errorf("Invalid key: cannot contain more than 1 \"/\"")
	}

	// Label key includes optional DNS name
	if len(fullKey) == 2 {
		if len(fullKey[0]) > 253 {
			return false, ErrInvalidLabelKeyHostnameLength
		}
		if len(fullKey[1]) > 63 {
			return false, ErrInvalidLabelKeyNameLength
		}
		validHostname, err := regexp.MatchString(validHostnameRegex, fullKey[0])
		if err != nil {
			return false, err
		}
		validKeyName, err := regexp.MatchString(validLabelKeyNameRegex, fullKey[1])
		if err != nil {
			return false, err
		}
		return (validHostname && validKeyName), nil
	}

	// Label key name only
	if len(key) > 63 {
		return false, ErrInvalidLabelKeyNameLength
	}
	return regexp.MatchString(validLabelKeyNameRegex, key)
}

func ValidLabelValue(value string) (bool, error) {
	if len(value) > 63 {
		return false, ErrInvalidLabelValueLength
	}
	return regexp.MatchString(validLabelValueRegex, value)
}

func PodDeleteLabel(pod *v1.Pod, key string) {
	delete(pod.ObjectMeta.Labels, key)
}

// Delete the labels with the given prefix whose keys are not in newLabels
// or if the corresponding values are not equal.
func PodDeleteOldLabelsWithPrefix(pod *v1.Pod, prefix string, newLabels map[string]string) {
	for key, val := range pod.ObjectMeta.Labels {
		expectedVal, ok := newLabels[key]
		// Old label not new labels
		if (!ok || val != expectedVal) && strings.HasPrefix(key, prefix) {
			PodDeleteLabel(pod, key)
		}
	}
}

func PodAddOrUpdateAnnotation(pod *v1.Pod, key, value string) {
	if pod.ObjectMeta.Annotations == nil {
		pod.ObjectMeta.Annotations = map[string]string{}
	}
	pod.ObjectMeta.Annotations[key] = value
}

func PodAddOrUpdateAnnotations(pod *v1.Pod, annotations map[string]string) {
	for k, v := range annotations {
		PodAddOrUpdateAnnotation(pod, k, v)
	}
}
