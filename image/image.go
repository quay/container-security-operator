package image

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	log "github.com/sirupsen/logrus"
)

const (
	dockerhub          = "docker.io"
	dockerhubNamespace = "library"

	validHostnameRegex   = `^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9][:\d+]*)$`
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

// ParsePullSecret parses a kubernetes secret containing image pull credentials. Return either a
// valid parsed secret or an error. If the secret does not exist and empty DockerConfigJson ref
// is returned.
func ParsePullSecret(ctx context.Context, secretClient corev1.SecretInterface, name string) (*DockerConfigJson, error) {
	secret, err := secretClient.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return &DockerConfigJson{Auths: map[string]DockerAuth{}}, nil
		}
		return nil, err
	}

	config := new(DockerConfigJson)
	switch secret.Type {
	case v1.SecretTypeDockercfg:
		data := secret.Data[v1.DockerConfigKey]
		if err := json.Unmarshal(data, &config.Auths); err != nil {
			return nil, err
		}
	case v1.SecretTypeDockerConfigJson:
		data := secret.Data[v1.DockerConfigJsonKey]
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown pull secret type: %s", secret.Type)
	}

	return config, nil
}

func ParsePullSecrets(ctx context.Context, secretClient corev1.SecretInterface, pullSecretRefs []v1.LocalObjectReference) (*DockerConfigJson, error) {
	dockerJsonConfig := &DockerConfigJson{Auths: map[string]DockerAuth{}}
	for _, secretRef := range pullSecretRefs {
		config, err := ParsePullSecret(ctx, secretClient, secretRef.Name)
		if err != nil {
			return nil, fmt.Errorf("Unable to process pull secret %q: %s", secretRef.Name, err)
		}

		for host, auth := range config.Auths {
			dockerJsonConfig.Auths[host] = auth
		}
	}

	return dockerJsonConfig, nil
}

// Formats:
//
//	{scheme}://{repo}@{digest} (images from dockerhub)
//	{scheme}://{namespace}/{repo}@{digest} (images from dockerhub)
//	{scheme}://{host}/{namespace}/{repo}@{digest}
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
		return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
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
		repoDigest := strings.SplitN(img, "@", 2)
		if len(repoDigest) != 2 {
			return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
		}

		// Dockerhub top-level namespace
		// Format: {repo}@{digest}
		host = dockerhub
		namespace = dockerhubNamespace
		repository = repoDigest[0]
		digest = repoDigest[1]
	} else if !strings.ContainsAny(img[:i], ".:") && img[:i] != "localhost" {
		// Dockerhub
		// Format: {namespace}/{repo}@{digest}
		namespaceRepoDigest := strings.Split(img, "/")
		repoDigest := strings.SplitN(namespaceRepoDigest[1], "@", 2)
		if len(repoDigest) != 2 {
			return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
		}

		host = dockerhub
		namespace = namespaceRepoDigest[0]
		repository = repoDigest[0]
		digest = repoDigest[1]
	} else {
		// Full registry path
		// Format: {host}/{namespace}/{repo}@{digest}
		hostRepopath := strings.SplitN(img, "/", 2)
		if len(hostRepopath) != 2 {
			return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
		}

		host = hostRepopath[0]
		imagePath := hostRepopath[1]
		splitImagePath := strings.Split(imagePath, "/")
		if len(splitImagePath) <= 1 {
			return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
		}

		repoAndDigest := splitImagePath[len(splitImagePath)-1]
		splitRepoDigest := strings.Split(repoAndDigest, "@")
		if len(splitRepoDigest) != 2 {
			return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
		}

		repository = splitRepoDigest[0]
		digest = splitRepoDigest[1]
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
		return nil, fmt.Errorf("Invalid imageID format: %s", imageID)
	}

	image := &Image{
		Host:       host,
		Namespace:  namespace,
		Repository: repository,
		Digest:     digest,
	}

	return image, nil
}

func ParseContainer(pod *v1.Pod, containerName string) (*Image, error) {
	// Get the container
	var container v1.Container
	for _, c := range pod.Spec.Containers {
		if c.Name == containerName {
			container = c
			break
		}
	}
	if container.Name != containerName {
		return nil, fmt.Errorf("unable to find container: %s", containerName)
	}

	// Get the container status
	var containerStatus v1.ContainerStatus
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == containerName {
			containerStatus = cs
			break
		}
	}
	if containerStatus.Name != containerName {
		return nil, fmt.Errorf("unable to find container status for container: %s", containerName)
	}

	// Parse imageID (digest)
	// cri-o will set the imageID to a random digest, in which case fallback to
	// container.image. We cannot rely on containerstatus.image as it will not always
	// point to the image that was specified in the pod spec
	var imageID string
	if regexp.MustCompile("^[a-zA-Z0-9_]*$").MatchString(containerStatus.ImageID) {
		imageID = container.Image
		digest := strings.SplitN(imageID, "@", 2)
		if len(digest) != 2 {
			return nil, fmt.Errorf("both image fields in container and containerStatus do not contain digest: %s", imageID)
		}
	} else {
		imageID = containerStatus.ImageID
	}
	image, err := ParseImageID(imageID)
	if err != nil {
		return nil, err
	}

	// Set container name
	image.ContainerName = container.Name

	// Set container id
	image.ContainerID = containerStatus.ContainerID

	// Check if image was pulled by digest or tag
	if len(strings.SplitN(container.Image, "@", 2)) > 1 {
		return image, nil
	}

	// Set tag name
	s := strings.Split(container.Image, ":")
	if len(s) != 2 && len(s) != 3 {
		return nil, fmt.Errorf("Wrong image format: %s", container.Image)
	}

	tagname := s[len(s)-1]
	if len(tagname) == 0 {
		return nil, fmt.Errorf("Empty Tag")
	}
	image.Tag = s[len(s)-1]

	return image, nil
}
