package image

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

func generatePod(name, image, imageID string) v1.Pod {
	return v1.Pod{
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  name,
					Image: image,
				},
			},
		},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{
				{
					Name:    name,
					Image:   image,
					ImageID: imageID,
				},
			},
		},
	}
}

var imageTable = []struct {
	imageID string

	expectedHost       string
	expectedNamespace  string
	expectedRepository string
	expectedDigest     string

	expectedError error
}{
	{
		"docker-pullable://quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"quay.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		nil,
	},
	{
		"docker-pullable://nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
		"docker.io",
		"library",
		"nginx",
		"sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
		nil,
	},
	{
		"docker-pullable://quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		nil,
	},
	{
		"docker-pullable://quay/redis--test@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker.io",
		"quay",
		"redis--test",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		nil,
	},
	{
		"quay/redis--test@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker.io",
		"quay",
		"redis--test",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		nil,
	},
	{
		"docker-pullable://quay.io/alecmerdler/bbb@sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		"quay.io",
		"alecmerdler",
		"bbb",
		"sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		nil,
	},
	{
		"sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		"",
		"",
		"",
		"",
		fmt.Errorf("Invalid imageID format: %s", "sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3"),
	},
	{
		"docker-pullable://my.registry.in.the.wild:9999/library/image@sha256:deadb33f99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		"my.registry.in.the.wild:9999",
		"library",
		"image",
		"sha256:deadb33f99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		nil,
	},
}

func TestParseImageID(t *testing.T) {
	for _, tt := range imageTable {
		var image = &Image{
			Host:       tt.expectedHost,
			Namespace:  tt.expectedNamespace,
			Repository: tt.expectedRepository,
			Digest:     tt.expectedDigest,
		}
		parsedImageID, err := ParseImageID(tt.imageID)
		if tt.expectedError != nil {
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
		} else if !reflect.DeepEqual(image, parsedImageID) {
			t.Errorf("Incorrectly parsed %s as %+v: %s", tt.imageID, parsedImageID, err)
		}
	}
}

var containerStatusTable = []struct {
	// Container status
	name    string
	image   string
	imageID string

	// Expected values
	containername string
	host          string
	namespace     string
	repository    string
	digest        string
	tag           string

	expectedError error
}{
	{
		"my-test-repository",
		"QUAY:443/my-test-namespace/my-test-repository",
		"docker-pullable://QUAY:443/my-test-namespace/my-test-repository@sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"my-test-repository",
		"QUAY:443",
		"my-test-namespace",
		"my-test-repository",
		"sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"latest",
		nil,
	},
	{
		"my-test-repository",
		"quay.io/my-test-namespace/my-test-repository",
		"docker-pullable://quay.io/my-test-namespace/my-test-repository@sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"my-test-repository",
		"quay.io",
		"my-test-namespace",
		"my-test-repository",
		"sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"latest",
		nil,
	},
	{
		"redis",
		"redis",
		"docker-pullable://redis@sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"redis",
		"docker.io",
		"library",
		"redis",
		"sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"latest",
		nil,
	},
	{
		"my-test-repository",
		"QUAY:443/my-test-namespace/my-test-repository@sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"cf879a45faaacd2806705321f157c4c77682c7599589fed65d80f19bb61615a6",

		"my-test-repository",
		"QUAY:443",
		"my-test-namespace",
		"my-test-repository",
		"sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"",

		nil,
	},
	{
		"my-test-repository",
		"QUAY:443/my-test-namespace/my-test-repository:latest",
		"docker-pullable://QUAY:443/my-test-namespace/my-test-repository@sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"my-test-repository",
		"QUAY:443",
		"my-test-namespace",
		"my-test-repository",
		"sha256:c549c6151dd8f4098fd02198913c0f6c55b240b156475588257f19d57e7b1fba",
		"latest",
		nil,
	},
	{
		"redis",
		"quay.io/quay/redis:latest",
		"docker-pullable://quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",

		"redis",
		"quay.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"latest",

		nil,
	},
	{
		"nginx",
		"nginx:latest",
		"docker-pullable://nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",

		"nginx",
		"docker.io",
		"library",
		"nginx",
		"sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
		"latest",

		nil,
	},
	{
		"redis",
		"quay/redis:latest",
		"docker-pullable://quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",

		"redis",
		"docker.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"latest",

		nil,
	},
	{
		"redis",
		"quay/redis--test:latest",
		"docker-pullable://quay/redis--test@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",

		"redis",
		"docker.io",
		"quay",
		"redis--test",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"latest",

		nil,
	},
	{
		"bbb",
		"quay.io/alecmerdler/bbb:scrape",
		"docker-pullable://quay.io/alecmerdler/bbb@sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",

		"bbb",
		"quay.io",
		"alecmerdler",
		"bbb",
		"sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		"scrape",

		nil,
	},
	{
		"redis",
		"quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker-pullable://quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",

		"redis",
		"docker.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"",

		nil,
	},
	{
		"redis",
		"quay.io/redis:sometag",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",

		"",
		"",
		"",
		"",
		"",
		"",

		fmt.Errorf("Invalid imageID format: %s", "sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"),
	},
	{
		"my-test-repository",
		"QUAY:443/my-test-namespace/my-test-repository:latest",
		"cf879a45faaacd2806705321f157c4c77682c7599589fed65d80f19bb61615a6",

		"",
		"",
		"",
		"",
		"",
		"",

		fmt.Errorf("both image fields in container and containerStatus do not contain digest: %s", "QUAY:443/my-test-namespace/my-test-repository:latest"),
	},
}

func TestParseContainerStatus(t *testing.T) {
	for _, tt := range containerStatusTable {
		pod := generatePod(tt.name, tt.image, tt.imageID)
		var image = &Image{
			ContainerName: tt.containername,
			Host:          tt.host,
			Namespace:     tt.namespace,
			Repository:    tt.repository,
			Digest:        tt.digest,
			Tag:           tt.tag,
		}

		parsedContainerStatus, err := ParseContainer(&pod, tt.name)
		if tt.expectedError != nil {
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
		} else if !reflect.DeepEqual(image, parsedContainerStatus) {
			t.Errorf("Incorrectly parsed %+v as %+v", pod, parsedContainerStatus)
		}
	}
}

var imageIDTable = []struct {
	imageID        string
	tag            string
	expectedString string
	expectedError  error
}{
	{
		imageID:        "docker-pullable://quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "testTag",
		expectedString: "quay.io/quay/redis:testTag",
		expectedError:  nil,
	},
	{
		imageID:        "docker-pullable://nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
		tag:            "testTag",
		expectedString: "nginx:testTag",
		expectedError:  nil,
	},
	{
		imageID:        "docker-pullable://quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "testTag",
		expectedString: "quay/redis:testTag",
		expectedError:  nil,
	},
	{
		imageID:        "docker-pullable://quay/redis--test@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "testTag",
		expectedString: "quay/redis--test:testTag",
		expectedError:  nil,
	},
	{
		imageID:        "quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "testTag",
		expectedString: "quay.io/quay/redis:testTag",
		expectedError:  nil,
	},
	{
		imageID:        "docker-pullable://quay.io/alecmerdler/bbb@sha256:24c6258b99cd427d0c3003e2878159de269f96c4ffbdeceaf9373ea3a31866b3",
		tag:            "scrape",
		expectedString: "quay.io/alecmerdler/bbb:scrape",
		expectedError:  nil,
	},
	{
		imageID:        "quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "",
		expectedString: "quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		expectedError:  nil,
	},
	{
		imageID:        "sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		tag:            "",
		expectedString: "",
		expectedError:  fmt.Errorf("Invalid imageID format: %s", "sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e"),
	},
}

func TestStringIDRepresentations(t *testing.T) {
	for _, tt := range imageIDTable {
		image, err := ParseImageID(tt.imageID)
		if tt.expectedError != nil {
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err)
		} else {
			image.Tag = tt.tag
			expectedImageID := strings.TrimPrefix(tt.imageID, "docker-pullable://")
			assert.Equal(t, expectedImageID, image.IDString())
			assert.Equal(t, tt.expectedString, image.String())
		}
	}
}
