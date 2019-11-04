package quay

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/quay/container-security-operator/secscan/rest"
)

const (
	wellKnownEndpoint = "/.well-known/app-capabilities"
)

type WellknownInterface interface {
	AppCapabilities() (*AppCapabilities, error)
}

type WellknownClient struct {
	restClient        rest.Interface
	wellKnownEndpoint string
}

func NewWellknownClient(baseUrl *url.URL, wellKnownEndpoint, versionedAPIPath string) (*WellknownClient, error) {
	c, err := rest.NewRESTClient(baseUrl, versionedAPIPath, http.DefaultClient)
	if err != nil {
		return nil, err
	}
	wc := &WellknownClient{
		restClient:        c,
		wellKnownEndpoint: wellKnownEndpoint,
	}
	return wc, nil
}

func (c *WellknownClient) AppCapabilities() (*AppCapabilities, error) {
	resp, err := c.restClient.Get().Path(c.wellKnownEndpoint).Do()
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

	var appCapabilities AppCapabilities
	err = json.Unmarshal(body, &appCapabilities)
	if err != nil {
		// Error parsing json
		return nil, err
	}

	return &appCapabilities, nil
}

type Capabilities struct {
	ViewImage struct {
		UrlTemplate string `json:"url-template"`
	} `json:"io.quay.view-image"`
	ManifestSecurity struct {
		RestApiTemplate string `json:"rest-api-template"`
	} `json:"io.quay.manifest-security"`
	ImageSecurity struct {
		RestApiTemplate string `json:"rest-api-template"`
	} `json:"io.quay.image-security"`
}

type AppCapabilitiesInterface interface {
	ViewImageTemplate() (string, error)
	ManifestSecurityTemplate() (string, error)
	ImageSecurityTemplate() (string, error)
}

type AppCapabilities struct {
	AppName      string       `json:"appName"`
	Capabilities Capabilities `json:"capabilities"`
}

func (ac *AppCapabilities) ViewImageTemplate() (string, error) {
	viewImage := ac.Capabilities.ViewImage
	urlTemplate := viewImage.UrlTemplate
	if len(urlTemplate) == 0 {
		return urlTemplate, fmt.Errorf("No view image capabilities")
	}
	return urlTemplate, nil
}

func (ac *AppCapabilities) ManifestSecurityTemplate() (string, error) {
	manifestSecurity := ac.Capabilities.ManifestSecurity
	restApiTemplate := manifestSecurity.RestApiTemplate
	if len(restApiTemplate) == 0 {
		return restApiTemplate, fmt.Errorf("No manifest security capabilities")
	}
	return restApiTemplate, nil
}

func (ac *AppCapabilities) ImageSecurityTemplate() (string, error) {
	imageSecurity := ac.Capabilities.ImageSecurity
	restApiTemplate := imageSecurity.RestApiTemplate
	if len(restApiTemplate) == 0 {
		return restApiTemplate, fmt.Errorf("No image security capabilities")
	}
	return restApiTemplate, nil
}
