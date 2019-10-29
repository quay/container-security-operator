package rest

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Interface interface {
	Verb(verb string) *Request
	Get() *Request
}

// Implenents Interface
type RESTClient struct {
	base             *url.URL
	versionedAPIPath string
	Client           *http.Client
}

func NewRESTClient(baseURL *url.URL, versionedAPIPath string, client *http.Client) (*RESTClient, error) {
	base := *baseURL
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery = ""
	base.Fragment = ""
	return &RESTClient{
		base:             &base,
		versionedAPIPath: versionedAPIPath,
		Client:           client,
	}, nil
}

func (c *RESTClient) Version() string {
	return c.versionedAPIPath
}

func (c *RESTClient) Get() *Request {
	return c.Verb("GET")
}

func (c *RESTClient) Verb(verb string) *Request {
	return NewRequest(c.Client, verb, c.base, c.versionedAPIPath)
}

// RoundTripper for bearer auth
type bearerAuthRoundTripper struct {
	bearer string
	rt     http.RoundTripper
}

func NewBearerAuthRoundTripper(bearer string, rt http.RoundTripper) http.RoundTripper {
	return &bearerAuthRoundTripper{bearer, rt}
}

func (rt *bearerAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(req.Header.Get("Authorization")) != 0 {
		return rt.rt.RoundTrip(req)
	}

	req = CloneRequest(req)

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", rt.bearer))
	return rt.rt.RoundTrip(req)
}

// Create shallow copy of request with deep copy of the headers
func CloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)

	// shallow clone
	*r = *req
	// deep copy headers
	r.Header = CloneHeader(req.Header)

	return r
}

func CloneHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}
