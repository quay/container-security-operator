package secscan

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
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
	replacer := strings.NewReplacer("{namespace}", image.Namespace, "{reponame}", image.Repository, "{digest}", image.Digest)
	requestURI := replacer.Replace(template)
	url, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse security manifest URL %s: %w", requestURI, err)
	}

	req := rest.NewRequest(http.DefaultClient, "GET", url, "")
	req = req.SetParam("features", strconv.FormatBool(features))
	req = req.SetParam("vulnerabilities", strconv.FormatBool(vulnerabilities))
	resp, err := req.Do()
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Request returned non-200 response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
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
