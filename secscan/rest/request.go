package rest

import (
	"net/http"
	"net/url"
	"path"
)

// Implements HTTPClient
type Request struct {
	client HTTPClient

	verb    string
	baseURL *url.URL

	pathPrefix string
	subpath    string
	params     url.Values
	headers    http.Header

	// Quay specific resources
	// ...
}

func NewRequest(client HTTPClient, verb string, baseURL *url.URL, versionedAPIPath string) *Request {
	pathPrefix := "/"
	if baseURL != nil {
		pathPrefix = path.Join(pathPrefix, baseURL.Path)
	}
	r := &Request{
		client:     client,
		verb:       verb,
		baseURL:    baseURL,
		pathPrefix: path.Join(pathPrefix, versionedAPIPath),
	}
	return r
}

func (r *Request) Path(path string) *Request {
	r.pathPrefix = ""
	r.subpath = path
	return r
}

func (r *Request) SubPath(subpath string) *Request {
	r.subpath = subpath
	return r
}

func (r *Request) SetParam(key, value string) *Request {
	if r.params == nil {
		r.params = make(url.Values)
	}
	r.params[key] = append(r.params[key], value)
	return r
}

func (r *Request) SetHeader(key, value string) *Request {
	if r.headers == nil {
		r.headers = http.Header{}
	}
	r.headers.Set(key, value)
	return r
}

func (r *Request) Do() (*http.Response, error) {
	req, err := http.NewRequest(r.verb, r.URL().String(), nil)
	if err != nil {
		return nil, err
	}
	for k, headers := range r.headers {
		for _, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return r.client.Do(req)
}

// Return the current Request working url
func (r *Request) URL() *url.URL {
	// Join the path prefix and subpath
	p := r.pathPrefix
	p = path.Join(p, r.subpath)

	u := &url.URL{}
	if r.baseURL != nil {
		*u = *r.baseURL
	}
	u.Path = p

	q := url.Values{}
	for key, values := range r.params {
		for _, value := range values {
			q.Add(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u
}

func (r *Request) Headers() *http.Header {
	return &r.headers
}

type Result struct {
	body        []byte
	contentType string
	err         error
	statusCode  int
}
