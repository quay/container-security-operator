package secscan

// Common types for security scanners

import (
	"encoding/json"

	secscanv1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	"github.com/quay/container-security-operator/image"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . Interface

type Interface interface {
	Wellknown(host, endpoint string) (WellknownInterface, error)
	GetLayerDataFromTemplate(manifestTemplate string, image *image.Image, features, vulnerabilities bool) (*Layer, error)
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . WellknownInterface

type WellknownInterface interface {
	ViewImageTemplate() (string, error)
	ManifestSecurityTemplate() (string, error)
	ImageSecurityTemplate() (string, error)
}

type Response struct {
	Status string `json:"status,omitempty"`
	Data   Data   `json:"data,omitempty"`
}

type Data struct {
	Layer Layer `json:"Layer,omitempty"`
}

type Layer struct {
	Name             string            `json:"Name,omitempty"`
	NamespaceName    string            `json:"NamespaceName,omitempty"`
	Path             string            `json:"Path,omitempty"`
	Headers          map[string]string `json:"Headers,omitempty"`
	ParentName       string            `json:"ParentName,omitempty"`
	Format           string            `json:"Format,omitempty"`
	IndexedByVersion int               `json:"IndexedByVersion,omitempty"`
	Features         []*Feature        `json:"Features,omitempty"`
}

type Feature struct {
	Name            string           `json:"Name,omitempty"`
	NamespaceName   string           `json:"NamespaceName,omitempty"`
	VersionFormat   string           `json:"VersionFormat,omitempty"`
	Version         string           `json:"Version,omitempty"`
	Vulnerabilities []*Vulnerability `json:"Vulnerabilities,omitempty"`
	AddedBy         string           `json:"AddedBy,omitempty"`
}

func (f *Feature) ToSecscanFeature() *secscanv1alpha1.Feature {
	vulnerabilities := []*secscanv1alpha1.Vulnerability{}
	for _, v := range f.Vulnerabilities {
		vulnerabilities = append(vulnerabilities, v.ToSecscanVulnerability())
	}
	return &secscanv1alpha1.Feature{
		Name:            f.Name,
		VersionFormat:   f.VersionFormat,
		NamespaceName:   f.NamespaceName,
		Version:         f.Version,
		Vulnerabilities: vulnerabilities,
	}
}

type Vulnerability struct {
	Name          string          `json:"Name,omitempty"`
	NamespaceName string          `json:"NamespaceName,omitempty"`
	Description   string          `json:"Description,omitempty"`
	Link          string          `json:"Link,omitempty"`
	Severity      string          `json:"Severity,omitempty"`
	Metadata      json.RawMessage `json:"Metadata,omitempty"`
	FixedBy       string          `json:"FixedBy,omitempty"`
}

func (v *Vulnerability) ToSecscanVulnerability() *secscanv1alpha1.Vulnerability {
	return &secscanv1alpha1.Vulnerability{
		Name:          v.Name,
		NamespaceName: v.NamespaceName,
		Description:   v.Description,
		Link:          v.Link,
		FixedBy:       v.FixedBy,
		Severity:      v.Severity,
		Metadata:      string(v.Metadata),
	}
}
