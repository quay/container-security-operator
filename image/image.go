package image

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	log "github.com/sirupsen/logrus"
)

const (
	dockerhub          = "docker.io"
	dockerhubNamespace = "library"

	validHostnameRegex   = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9])$`
	validNamespaceRegex  = `([a-z0-9_-]{2,255})$`
	validRepositoryRegex = `^([a-z0-9_-])+`
	validDigestRegex     = `^[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*[:][[:xdigit:]]{32,}$`
)

var (
	hostnameRegex   = regexp.MustCompile(validHostnameRegex)
	namespaceRegex  = regexp.MustCompile(validNamespaceRegex)
	repositoryRegex = regexp.MustCompile(validRepositoryRegex)
	digestRegex     = regexp.MustCompile(validDigestRegex)
)

type DockerConfigJson struct {
	Auths map[string]DockerAuth `json:"auths,omitempty"`
}

type DockerAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Email    string `json:"email,omitempty"`
	Auth     string `json:"auth,omitempty"`
}

func ParsePullSecrets(secretClient corev1.SecretInterface, pullSecretRefs []v1.LocalObjectReference) (*DockerConfigJson, error) {
	dockerJsonConfig := &DockerConfigJson{Auths: map[string]DockerAuth{}}
	for _, secretRef := range pullSecretRefs {
		secret, err := secretClient.Get(secretRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("Unable to get pull secret: %s", secretRef.Name)
		}

		secretData := secret.Data[strings.ReplaceAll(string(secret.Type), "kubernetes.io/", ".")]

		var config *DockerConfigJson
		if err = json.Unmarshal(secretData, &config); err != nil {
			return nil, fmt.Errorf("Failed to parse pull secret: %s", secretRef.Name)
		}

		for host, auth := range config.Auths {
			dockerJsonConfig.Auths[host] = auth
		}
	}

	return dockerJsonConfig, nil
}

// Formats:
//     {scheme}://{repo}@{digest} (images from dockerhub)
//     {scheme}://{namespace}/{repo}@{digest} (images from dockerhub)
//     {scheme}://{host}/{namespace}/{repo}@{digest}
type Image struct {
	ContainerName string
	ContainerID   string
	Host          string
	Namespace     string
	Repository    string
	Digest        string
	Tag           string
	Auth          string
}

// Return the image manifest id (docker-pullable)
// See https://github.com/kubernetes/kubernetes/pull/34473
func (img *Image) URL(subpaths ...string) string {
	sl := []string{}
	for _, subpath := range subpaths {
		sl = append(sl, subpath)
	}
	return strings.Join(sl, "/")
}

func (img *Image) IDString() string {
	// Check for docker defaults
	var r string
	if img.Host == dockerhub {
		if img.Namespace == dockerhubNamespace {
			r = img.Repository
		} else {
			r = img.URL(img.Namespace, img.Repository)
		}
	} else {
		r = img.URL(img.Host, img.Namespace, img.Repository)
	}

	return strings.Join([]string{r, img.Digest}, "@")
}

func (img *Image) String() string {
	// Check for docker defaults
	var r string
	if img.Host == dockerhub {
		if img.Namespace == dockerhubNamespace {
			r = img.Repository
		} else {
			r = img.URL(img.Namespace, img.Repository)
		}
	} else {
		r = img.URL(img.Host, img.Namespace, img.Repository)
	}

	if len(img.Tag) == 0 {
		return strings.Join([]string{r, img.Digest}, "@")
	}

	return strings.Join([]string{r, img.Tag}, ":")
}

func ParseImageID(imageID string) (*Image, error) {
	var img, host, namespace, repository, digest string

	// https://github.com/kubernetes/kubernetes/issues/46255
	imageIDTokens := strings.SplitN(imageID, "://", 2)
	if len(imageIDTokens) > 2 {
		return nil, fmt.Errorf("Invalid imageID format")
	}
	if len(imageIDTokens) == 2 {
		if imageIDTokens[0] != "docker-pullable" {
			return nil, fmt.Errorf("Image not using manifest digest format")
		}
		img = imageIDTokens[1]
	} else {
		img = imageIDTokens[0]
	}

	i := strings.IndexRune(img, '/')
	if i == -1 {
		// Dockerhub top-level namespace
		// Format: {repo}@{digest}
		repoDigest := strings.SplitN(img, "@", 2)
		host = dockerhub
		namespace = dockerhubNamespace
		repository = repoDigest[0]
		digest = repoDigest[1]
	} else if !strings.ContainsAny(img[:i], ".:") && img[:i] != "localhost" {
		// Dockerhub
		// Format: {namespace}/{repo}@{digest}
		namespaceRepoDigest := strings.Split(img, "/")
		repoDigest := strings.SplitN(namespaceRepoDigest[1], "@", 2)
		host = dockerhub
		namespace = namespaceRepoDigest[0]
		repository = repoDigest[0]
		digest = repoDigest[1]
	} else {
		// Full registry path
		// Format: {host}/{namespace}/{repo}@{digest}
		host = strings.SplitN(img, "/", 2)[0]
		imagePath := strings.SplitN(img, "/", 2)[1]
		splitImagePath := strings.Split(imagePath, "/")

		imageDigest := splitImagePath[len(splitImagePath)-1]
		repository = strings.Split(imageDigest, "@")[0]
		digest = strings.Split(imageDigest, "@")[1]
		namespace = strings.Join(splitImagePath[:len(splitImagePath)-1], "/")
	}

	validHost := hostnameRegex.MatchString(host)
	validNamespace := namespaceRegex.MatchString(namespace)
	validRepository := repositoryRegex.MatchString(repository)
	validDigest := digestRegex.MatchString(digest)
	if !validHost || !validNamespace || !validRepository || !validDigest {
		log.WithFields(log.Fields{
			"host":            host,
			"namespace":       namespace,
			"repository":      repository,
			"digest":          digest,
			"validHost":       validHost,
			"validNamespace":  validNamespace,
			"validRepository": validRepository,
			"validDigest":     validDigest,
		}).Error("Invalid imageID format")
		return nil, fmt.Errorf("Invalid imageID format")
	}

	image := &Image{
		Host:       host,
		Namespace:  namespace,
		Repository: repository,
		Digest:     digest,
	}

	return image, nil
}

func ParseContainerStatus(containerStatus v1.ContainerStatus) (*Image, error) {
	// Parse imageID (digest)
	image, err := ParseImageID(containerStatus.ImageID)
	if err != nil {
		return nil, err
	}

	// Set container name
	image.ContainerName = containerStatus.Name

	// Set container id
	image.ContainerID = containerStatus.ContainerID

	// Check if image was pulled by digest or tag
	if len(strings.SplitN(containerStatus.Image, "@", 2)) > 1 {
		return image, nil
	}

	// Set tag name
	s := strings.Split(containerStatus.Image, ":")
	if len(s) != 2 {
		return nil, fmt.Errorf("Wrong image format")
	}

	tagname := s[len(s)-1]
	if len(tagname) == 0 {
		return nil, fmt.Errorf("Empty Tag")
	}
	image.Tag = s[len(s)-1]

	return image, nil
}
