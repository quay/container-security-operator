package image

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"k8s.io/api/core/v1"
)

var imageTable = []struct {
	imageID    string
	host       string
	namespace  string
	repository string
	digest     string
}{
	{
		"docker-pullable://quay.io/quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"quay.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
	},
	{
		"docker-pullable://nginx@sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
		"docker.io",
		"library",
		"nginx",
		"sha256:0d71ff22db29a08ac7399d1b35b0311c5b0cbe68d878993718275758811f652a",
	},
	{
		"docker-pullable://quay/redis@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker.io",
		"quay",
		"redis",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
	},
	{
		"docker-pullable://quay/redis--test@sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
		"docker.io",
		"quay",
		"redis--test",
		"sha256:94033a42da840b970fd9d2b04dae5fec56add2714ca674a758d030ce5acba27e",
	},
}

func TestParseImageID(t *testing.T) {
	for _, tt := range imageTable {
		var image = &Image{
			Host:       tt.host,
			Namespace:  tt.namespace,
			Repository: tt.repository,
			Digest:     tt.digest,
		}
		parsedImageID, _ := ParseImageID(tt.imageID)
		if !reflect.DeepEqual(image, parsedImageID) {
			t.Errorf("Incorrectly parsed %s as %+v", tt.imageID, parsedImageID)
		}
	}
}

var containerStatusTable = []struct {
	// Container status
	name    string
	image   string
	imageID string

	// Full image strings (docker)

	// Expected values
	containername string
	host          string
	namespace     string
	repository    string
	digest        string
	tag           string
}{
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
	},
}

func TestParseContainerStatus(t *testing.T) {
	for _, tt := range containerStatusTable {
		containerStatus := generateContainerStatus(tt.name, tt.image, tt.imageID)
		var image = &Image{
			ContainerName: tt.containername,
			Host:          tt.host,
			Namespace:     tt.namespace,
			Repository:    tt.repository,
			Digest:        tt.digest,
			Tag:           tt.tag,
		}

		parsedContainerStatus, err := ParseContainerStatus(containerStatus)
		if err != nil {
			t.Errorf("%s", err)
		}
		if !reflect.DeepEqual(image, parsedContainerStatus) {
			t.Errorf("Incorrectly parsed %+v as %+v", containerStatus, parsedContainerStatus)
		}
	}
}

func TestStringRepresentations(t *testing.T) {
	for _, tt := range containerStatusTable {
		var image = &Image{
			ContainerName: tt.containername,
			Host:          tt.host,
			Namespace:     tt.namespace,
			Repository:    tt.repository,
			Digest:        tt.digest,
			Tag:           tt.tag,
		}
		assert.Equal(t, tt.image, image.String())
		assert.Equal(t, tt.imageID, image.IDString())
	}
}

func generateContainerStatus(name, image, imageID string) v1.ContainerStatus {
	cs := v1.ContainerStatus{
		Name:    name,
		Image:   image,
		ImageID: imageID,
	}
	return cs
}
