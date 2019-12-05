package secscan

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/quay/container-security-operator/image"
)

var imageTestTable = []struct {
	template string
	img      *image.Image
	params   map[string]string

	expectedURL string
}{
	{
		"https://quay.io/api/v1/repository/{namespace}/{reponame}/manifest/{digest}/security",
		&image.Image{Namespace: "testnamespace", Repository: "testrepo", Digest: "sha256:123456", Auth: "somebase64string"},
		map[string]string{"features": "true", "vulnerabilities": "true"},
		"https://quay.io/api/v1/repository/testnamespace/testrepo/manifest/sha256:123456/security?features=true&vulnerabilities=true",
	},
	{
		"https://quay.io/api/v1/repository/{namespace}/{reponame}/manifest/{digest}/security",
		&image.Image{Namespace: "testnamespace", Repository: "testrepo", Digest: "sha256:123456", Auth: ""},
		map[string]string{"features": "true", "vulnerabilities": "true"},
		"https://quay.io/api/v1/repository/testnamespace/testrepo/manifest/sha256:123456/security?features=true&vulnerabilities=true",
	},
}

func TestBasicAuthenticationRequest(t *testing.T) {
	for _, tt := range imageTestTable {
		req, err := layerDataFromTemplateRequest(tt.template, "GET", tt.img, tt.params)
		assert.Nil(t, err)

		assert.Equal(t, req.URL().String(), tt.expectedURL)

		if tt.img.Auth != "" {
			authHeader := req.Headers().Get("Authorization")
			assert.Equal(t, authHeader, "Basic "+tt.img.Auth)
		}
	}
}
