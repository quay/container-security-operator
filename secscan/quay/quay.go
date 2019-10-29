package quay

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"path"
	"strconv"

	"github.com/coreos-inc/security-labeller/image"
	"github.com/coreos-inc/security-labeller/secscan"
)

type Quay struct {
	*WellknownClient
	*SecscanClient
}

func NewQuayClient(baseURL *url.URL, token string, apiVersion int) (*Quay, error) {
	// Create a WellknownClient
	wellKnownVersion := ""
	wellKnown, err := NewWellknownClient(baseURL, wellKnownEndpoint, wellKnownVersion)
	if err != nil {
		return nil, err
	}

	versionedAPIPath := "api/v" + strconv.Itoa(apiVersion)
	secscan, err := NewSecscanClient(baseURL, versionedAPIPath, token)

	q := &Quay{
		WellknownClient: wellKnown,
		SecscanClient:   secscan,
	}
	return q, nil
}

func (q *Quay) Wellknown() *WellknownClient {
	if q == nil {
		return nil
	}
	return q.WellknownClient
}

func (q *Quay) Secscan() *SecscanClient {
	if q == nil {
		return nil
	}
	return q.SecscanClient
}

func (q *Quay) GetLayerData(image *image.Image, features, vulnerabilities bool) (*secscan.Layer, error) {
	secscanClient := q.Secscan()
	req := secscanClient.restClient.Get()

	// Uses Quay's support for basic auth on security endpoints
	if image.Auth != "" {
		req = req.SetHeader("Authorization", fmt.Sprintf("Basic %s", image.Auth))
	}

	subpath := path.Join("repository", image.Namespace, image.Repository, "manifest", image.Digest, "security")

	req = req.SubPath(subpath)
	req = req.SetParam("features", strconv.FormatBool(features))
	req = req.SetParam("vulnerabilities", strconv.FormatBool(vulnerabilities))
	resp, err := req.Do()
	if err != nil {
		// Request error
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Request returned non-200 response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Error reading response body
		return nil, fmt.Errorf("failed to perform request: %v", err)
	}

	var security secscan.Response
	err = json.Unmarshal(body, &security)
	if err != nil {
		// Error parsing json
		return nil, err
	}

	if security.Status != "scanned" {
		return nil, fmt.Errorf("Image not scanned: %s", security.Status)
	}

	return &security.Data.Layer, nil

}

func (q *Quay) Ping() bool {
	// Check if Quay supports security scanning endpoint
	appCapabilities, err := q.Wellknown().AppCapabilities()
	if err != nil {
		return false
	}

	_, err = appCapabilities.ManifestSecurityTemplate()
	if err != nil {
		return false
	}

	return true
}
