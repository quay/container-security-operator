package secscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/quay/container-security-operator/image"
	"github.com/quay/container-security-operator/secscan/rest"
)

type Client struct{}

func NewClient() (*Client, error) {
	c := &Client{}
	return c, nil
}

func (c *Client) Wellknown(host, endpoint string) (WellknownInterface, error) {
	wellknownClient, err := NewWellknownClient(host, endpoint)
	if err != nil {
		return nil, err
	}
	return wellknownClient, nil
}

func (c *Client) GetLayerDataFromTemplate(template string, image *image.Image, features, vulnerabilities bool) (*Layer, error) {
	params := map[string]string{
		"features":        strconv.FormatBool(features),
		"vulnerabilities": strconv.FormatBool(vulnerabilities),
	}

	req, err := layerDataFromTemplateRequest(template, "GET", image, params)
	if err != nil {
		return nil, err
	}

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

	var securityResponse Response
	err = json.Unmarshal(body, &securityResponse)
	if err != nil {
		return nil, err
	}

	if securityResponse.Status != "scanned" {
		return nil, fmt.Errorf("Image not scanned: %s", securityResponse.Status)
	}

	return &securityResponse.Data.Layer, nil
}

func layerDataFromTemplateRequest(template, method string, img *image.Image, params map[string]string) (*rest.Request, error) {
	var userAgent string
	replacer := strings.NewReplacer("{namespace}", img.Namespace, "{reponame}", img.Repository, "{digest}", img.Digest)
	requestURI := replacer.Replace(template)
	url, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse security manifest URL %s: %w", requestURI, err)
	}

	req := rest.NewRequest(http.DefaultClient, "GET", url, "")
	if img.Auth != "" {
		req = req.SetHeader("Authorization", fmt.Sprintf("Basic %s", img.Auth))
	}

	env, isPresent := os.LookupEnv("QUAY_VERSION")
	if !isPresent {
		userAgent = "container-security-operator/1.0.6"
	} else {
		userAgent = env
	}

	req = req.SetHeader("User-Agent", userAgent)

	for key, val := range params {
		req = req.SetParam(key, val)
	}

	return req, err
}
