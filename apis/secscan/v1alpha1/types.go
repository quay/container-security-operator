package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// https://github.com/kubernetes/community/blob/master/contributors/devel/api-conventions.md#spec-and-status

type Feature struct {
	Name            string           `json:"name,omitempty"`
	VersionFormat   string           `json:"versionformat,omitempty"`
	NamespaceName   string           `json:"namespaceName,omitempty"`
	Version         string           `json:"version,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities,omitempty"`
}

type Vulnerability struct {
	Name          string `json:"name,omitempty"`
	NamespaceName string `json:"namespaceName,omitempty"`
	Description   string `json:"description,omitempty"`
	Link          string `json:"link,omitempty"`
	FixedBy       string `json:"fixedby,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Metadata      string `json:"metadata,omitempty"`
}

type ImageManifestVulnSpec struct {
	Image         string     `json:"image,omitempty"`
	Manifest      string     `json:"manifest,omitempty"`
	NamespaceName string     `json:"namespaceName,omitempty"`
	Features      []*Feature `json:"features,omitempty"`
}

type ImageManifestVulnStatus struct {
	LastUpdate      string `json:"lastUpdate,omitempty"`
	HighestSeverity string `json:"highestSeverity,omitempty"`

	UnknownCount    int `json:"unknownCount,omitempty"`
	NegligibleCount int `json:"negligibleCount,omitempty"`
	LowCount        int `json:"lowCount,omitempty"`
	MediumCount     int `json:"mediumCount,omitempty"`
	HighCount       int `json:"highCount,omitempty"`
	CriticalCount   int `json:"criticalCount,omitempty"`
	Defcon1Count    int `json:"defcon1Count,omitempty"`
	FixableCount    int `json:"fixableCount,omitempty"`

	// Map from pod's path to container ids
	AffectedPods map[string][]string `json:"affectedPods,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=true
type ImageManifestVuln struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ImageManifestVulnSpec `json:"spec,omitempty"`
	// +optional
	Status ImageManifestVulnStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:openapi-gen=true
type ImageManifestVulnList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []*ImageManifestVuln `json:"items"`
}
