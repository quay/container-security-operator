package quay

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/quay/container-security-operator/image"
	"github.com/quay/container-security-operator/secscan"
	"github.com/quay/container-security-operator/secscan/rest"
)

type SecscanClient struct {
	restClient rest.Interface
}

func NewSecscanClient(baseUrl *url.URL, versionedAPIPath, token string) (*SecscanClient, error) {
	httpClient := http.DefaultClient
	defaultTransport := http.DefaultTransport
	rt := rest.NewBearerAuthRoundTripper(token, defaultTransport)
	httpClient.Transport = rt

	c, err := rest.NewRESTClient(baseUrl, versionedAPIPath, httpClient)
	if err != nil {
		return nil, err
	}
	ss := &SecscanClient{
		restClient: c,
	}
	return ss, nil
}

func (c *SecscanClient) ManifestSecurity(namespace, repository, digest string, vulnerabilities bool) (*secscan.Response, error) {
	req := c.restClient.Get()

	subpath := path.Join("repository", namespace, repository, "manifest", digest, "security")

	req = req.SubPath(subpath)
	req = req.SetParam("vulnerabilities", "true")
	resp, err := req.Do()
	if err != nil {
		// Request error
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Error reading response body
		return nil, err
	}

	var security secscan.Response
	err = json.Unmarshal(body, &security)
	if err != nil {
		// Error parsing json
		return nil, err
	}

	return &security, nil
}

func (c *SecscanClient) ManifestSecurityFromTemplate(template, namespace, repository, digest string, vulnerability bool) (*secscan.Response, error) {
	replacer := strings.NewReplacer("{namespace}", namespace, "{reponame}", repository, "{digest}", digest)
	url := replacer.Replace(template)

	req := c.restClient.Get()
	req.Path(url)
	req = req.SetParam("vulnerabilities", "true")

	resp, err := req.Do()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		// Error reading response body
		return nil, err
	}

	var security secscan.Response
	err = json.Unmarshal(body, &security)
	if err != nil {
		// Error parsing json
		return nil, err
	}

	return &security, nil
}

func (c *SecscanClient) GetLayerData(image *image.Image, features, vulnerabilities bool) (*secscan.Layer, error) {
	req := c.restClient.Get()

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

// TODO(kleesc):
func (c *SecscanClient) Ping() bool {
	return true
}
