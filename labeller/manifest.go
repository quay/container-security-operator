package labeller

import (
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	secscanv1alpha1 "github.com/coreos-inc/security-labeller/apis/secscan/v1alpha1"
	secscanv1alpha1client "github.com/coreos-inc/security-labeller/generated/versioned/typed/secscan/v1alpha1"
	"github.com/coreos-inc/security-labeller/secscan"
)

var labelPrefix = "secscan"
var timestampLayout = "2006-01-02 15:04:05 -0700 MST"

type vulnerabilityCount struct {
	Unknown           int
	UnknownFixable    int
	Negligible        int
	NegligibleFixable int
	Low               int
	LowFixable        int
	Medium            int
	MediumFixable     int
	High              int
	HighFixable       int
	Critical          int
	CriticalFixable   int
	Defcon1           int
	Defcon1Fixable    int
}

func (c *vulnerabilityCount) TotalFixables() int {
	return c.UnknownFixable + c.NegligibleFixable + c.LowFixable + c.MediumFixable + c.HighFixable + c.CriticalFixable + c.Defcon1Fixable
}

func (c *vulnerabilityCount) Total() int {
	return c.Unknown + c.Negligible + c.Low + c.Medium + c.High + c.Critical + c.Defcon1
}

func (c *vulnerabilityCount) HighestSeverity() string {
	if c.Defcon1 > 0 {
		return secscan.Defcon1Severity
	} else if c.Critical > 0 {
		return secscan.CriticalSeverity
	} else if c.High > 0 {
		return secscan.HighSeverity
	} else if c.Medium > 0 {
		return secscan.MediumSeverity
	} else if c.Low > 0 {
		return secscan.LowSeverity
	} else if c.Negligible > 0 {
		return secscan.NegligibleSeverity
	} else if c.Unknown > 0 {
		return secscan.UnknownSeverity
	}
	return ""
}

func buildImageManifestVuln(namespace, image, manifestDigest string, layer *secscan.Layer) (*secscanv1alpha1.ImageManifestVuln, error) {
	name := manifestName(manifestDigest)

	imgManifestVuln := &secscanv1alpha1.ImageManifestVuln{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: make(map[string]string),
			Name:        name,
			Namespace:   namespace,
		},
		Spec: secscanv1alpha1.ImageManifestVulnSpec{
			Manifest:      manifestDigest,
			Image:         image,
			NamespaceName: layer.NamespaceName,
		},
		Status: secscanv1alpha1.ImageManifestVulnStatus{
			AffectedPods: make(map[string][]string),
		},
	}

	aggVulnCount := &vulnerabilityCount{}
	labels := make(map[string]string)
	vulnerableFeatures := []*secscanv1alpha1.Feature{}

	for _, feature := range layer.Features {
		vulnCount := 0
		for _, vulnerability := range feature.Vulnerabilities {
			vulnCount++
			switch vulnerability.Severity {
			case secscan.UnknownSeverity:
				aggVulnCount.Unknown++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.UnknownFixable++
				}
			case secscan.NegligibleSeverity:
				aggVulnCount.Negligible++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.NegligibleFixable++
				}
			case secscan.LowSeverity:
				aggVulnCount.Low++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.LowFixable++
				}
			case secscan.MediumSeverity:
				aggVulnCount.Medium++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.MediumFixable++
				}
			case secscan.HighSeverity:
				aggVulnCount.High++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.HighFixable++
				}
			case secscan.CriticalSeverity:
				aggVulnCount.Critical++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.CriticalFixable++
				}
			case secscan.Defcon1Severity:
				aggVulnCount.Defcon1++
				if len(vulnerability.FixedBy) > 0 {
					aggVulnCount.Defcon1Fixable++
				}
			default:
				return nil, fmt.Errorf("Unknown severity %s: not one of %v", vulnerability.Severity, secscan.Severities)
			}

			label := labelName(labelPrefix, vulnerability.Name)
			labels[label] = vulnerability.Severity
		}

		if vulnCount > 0 {
			vulnerableFeatures = append(vulnerableFeatures, feature.ToSecscanFeature())
		}
	}

	imgManifestVuln, _ = addAggregatedCountToStatus(aggVulnCount, imgManifestVuln)
	imgManifestVuln.Status.LastUpdate = time.Now().UTC().String()
	imgManifestVuln.Spec.Features = vulnerableFeatures
	imgManifestVuln.ObjectMeta.Labels = labels

	return imgManifestVuln, nil
}

func addAggregatedCountToStatus(aggVulnCount *vulnerabilityCount, manifest *secscanv1alpha1.ImageManifestVuln) (*secscanv1alpha1.ImageManifestVuln, bool) {
	if aggVulnCount.Total() == 0 {
		return manifest, false
	}
	manifest.Status.UnknownCount = aggVulnCount.Unknown
	manifest.Status.NegligibleCount = aggVulnCount.Negligible
	manifest.Status.LowCount = aggVulnCount.Low
	manifest.Status.MediumCount = aggVulnCount.Medium
	manifest.Status.HighCount = aggVulnCount.High
	manifest.Status.CriticalCount = aggVulnCount.Critical
	manifest.Status.Defcon1Count = aggVulnCount.Defcon1
	manifest.Status.FixableCount = aggVulnCount.TotalFixables()
	manifest.Status.HighestSeverity = aggVulnCount.HighestSeverity()

	return manifest, true
}

func manifestName(manifestDigest string) string {
	return fmt.Sprintf("%s", strings.ReplaceAll(manifestDigest, ":", "."))
}

func labelName(prefix, name string) string {
	return fmt.Sprintf("%s/%s", prefix, name)
}

func qualifiedName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func addAffectedPod(key, containerID string, manifest *secscanv1alpha1.ImageManifestVuln) (*secscanv1alpha1.ImageManifestVuln, bool) {
	changed := false
	if containerIds, ok := manifest.Status.AffectedPods[key]; ok {
		if !contains(containerIds, containerID) {
			containerIds = append(containerIds, containerID)
			changed = true
		}
		return manifest, changed
	}

	if manifest.Status.AffectedPods == nil {
		manifest.Status.AffectedPods = make(map[string][]string)
	}

	manifest.Status.AffectedPods[key] = append(manifest.Status.AffectedPods[key], containerID)
	manifest.ObjectMeta.Labels[key] = "true"

	changed = true
	return manifest, changed
}

func removeAffectedPod(key string, manifest *secscanv1alpha1.ImageManifestVuln) (*secscanv1alpha1.ImageManifestVuln, bool) {
	changed := false
	if _, ok := manifest.Status.AffectedPods[key]; ok {
		delete(manifest.Status.AffectedPods, key)
		delete(manifest.ObjectMeta.Labels, key)
		changed = true
	}
	return manifest, changed
}

func removeDanglingPods(validPodsKeys []string, manifest *secscanv1alpha1.ImageManifestVuln) (*secscanv1alpha1.ImageManifestVuln, bool) {
	changed := false
	for k, _ := range manifest.Status.AffectedPods {
		if !contains(validPodsKeys, k) {
			var updated bool
			manifest, updated = removeAffectedPod(k, manifest)
			changed = changed || updated
		}
	}
	return manifest, changed
}

func removeAffectedPodFromManifests(apiclient secscanv1alpha1client.ImageManifestVulnInterface, key string) error {
	listOptions := metav1.ListOptions{}
	manifestList, err := apiclient.List(listOptions)
	if err != nil {
		return fmt.Errorf("Failed to list ImageManifestVulns: %w", err)
	}

	for _, manifest := range manifestList.Items {
		if updatedManifest, changed := removeAffectedPod(key, manifest); changed {
			if _, err := apiclient.Update(updatedManifest); err != nil {
				return fmt.Errorf("Failed to update ImageManifestVuln: %w", err)
			}
		}
	}

	return nil
}

func garbageCollectManifests(podclient corev1.PodInterface, manifestclient secscanv1alpha1client.ImageManifestVulnInterface) error {
	podList, err := podclient.List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Failed to list pods: %w", err)
	}

	currentPodKeys := []string{}
	for _, pod := range podList.Items {
		currentPodKeys = append(currentPodKeys, qualifiedName(pod.Namespace, pod.Name))
	}

	manifestList, err := manifestclient.List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Failed to list ImageManifestVulns: %w", err)
	}

	for _, manifest := range manifestList.Items {
		var (
			updated         bool
			updatedManifest *secscanv1alpha1.ImageManifestVuln
		)
		updatedManifest, updated = removeDanglingPods(currentPodKeys, manifest)

		if len(updatedManifest.Status.AffectedPods) == 0 {
			if err := manifestclient.Delete(updatedManifest.Name, &metav1.DeleteOptions{}); err != nil {
				return fmt.Errorf("Failed to delete unreferenced ImageManifestVuln: %w", err)
			}
			continue
		}

		if updated {
			if _, err := manifestclient.Update(updatedManifest); err != nil {
				return fmt.Errorf("Failed to update ImageManifestVuln: %w", err)
			}
		}
	}

	return nil
}

func contains(s []string, i string) bool {
	for _, val := range s {
		if i == val {
			return true
		}
	}
	return false
}
