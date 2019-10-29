package rest

import (
	"net/http"
	"testing"
)

type testRoundTripper struct {
	Request  *http.Request
	Response *http.Response
	Err      error
}

func (rt *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.Request = req
	return rt.Response, rt.Err
}

func TestBearerAuthRoundTripper(t *testing.T) {
	rt := &testRoundTripper{}
	req := &http.Request{}
	NewBearerAuthRoundTripper("test", rt).RoundTrip(req)
	if rt.Request == nil {
		t.Fatalf("Unexpected nil request: %v", rt)
	}
	if rt.Request == req {
		t.Fatalf("RoundTripper should have copied request object: %#v", rt.Request)
	}
	if rt.Request.Header.Get("Authorization") != "Bearer test" {
		t.Errorf("Unexpected authorization header: %#v", rt.Request)
	}
}
