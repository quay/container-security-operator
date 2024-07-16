package secscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/quay/container-security-operator/secscan/rest"
)

const (
	wellKnownEndpoint = "/.well-known/app-capabilities"

	viewImageKeySuffix        = "view-image"
	manifestSecurityKeySuffix = "manifest-security"
	imageSecurityKeySuffix    = "image-security"

	urlTemplateKey     = "url-template"
	restApiTemplateKey = "rest-api-template"
)

type AppCapabilities struct {
	AppName      string              `json:"appName"`
	Capabilities map[string]Template `json:"capabilities"`
}

type Template map[string]interface{}

// Generate the template key from the given host and key suffix
// e.g. io.quay.manifest-security
func appCapabilityKey(host, keySuffix string) string {
	return strings.Join([]string{"io.quay", keySuffix}, ".")
}

type WellknownClient struct {
	host              string
	wellKnownEndpoint string
	appCapabilities   *AppCapabilities
}

func (wc *WellknownClient) RequestBaseURI() string {
	return "https://" + wc.host
}

func NewWellknownClient(host, wellKnownEndpoint string) (*WellknownClient, error) {
	c := &WellknownClient{
		host:              host,
		wellKnownEndpoint: wellKnownEndpoint,
		appCapabilities:   &AppCapabilities{},
	}

	baseUrl, err := url.ParseRequestURI(c.RequestBaseURI())
	if err != nil {
		return nil, fmt.Errorf("Failed to parse well-known URL %s: %w", c.RequestBaseURI(), err)
	}

	req := rest.NewRequest(http.DefaultClient, "GET", baseUrl, "")
	req = req.Path(c.wellKnownEndpoint)

	resp, err := req.Do()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Request returned non-200 response: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, c.appCapabilities)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (wc *WellknownClient) ViewImageTemplate() (string, error) {
	key := appCapabilityKey(wc.host, viewImageKeySuffix)
	viewImage := wc.appCapabilities.Capabilities[key]
	urlTemplate := viewImage[urlTemplateKey].(string)
	if len(urlTemplate) == 0 {
		return urlTemplate, fmt.Errorf("No view image capabilities")
	}
	return urlTemplate, nil
}

func (wc *WellknownClient) ManifestSecurityTemplate() (string, error) {
	key := appCapabilityKey(wc.host, manifestSecurityKeySuffix)
	manifestSecurity := wc.appCapabilities.Capabilities[key]
	restApiTemplate := manifestSecurity[restApiTemplateKey].(string)
	if len(restApiTemplate) == 0 {
		return restApiTemplate, fmt.Errorf("No manifest security capabilities")
	}
	return restApiTemplate, nil
}

func (wc *WellknownClient) ImageSecurityTemplate() (string, error) {
	key := appCapabilityKey(wc.host, imageSecurityKeySuffix)
	imageSecurity := wc.appCapabilities.Capabilities[key]
	restApiTemplate := imageSecurity[restApiTemplateKey].(string)
	if len(restApiTemplate) == 0 {
		return restApiTemplate, fmt.Errorf("No image security capabilities")
	}
	return restApiTemplate, nil
}
