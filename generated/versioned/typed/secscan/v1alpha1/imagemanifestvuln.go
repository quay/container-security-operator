/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/quay/container-security-operator/apis/secscan/v1alpha1"
	scheme "github.com/quay/container-security-operator/generated/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ImageManifestVulnsGetter has a method to return a ImageManifestVulnInterface.
// A group's client should implement this interface.
type ImageManifestVulnsGetter interface {
	ImageManifestVulns(namespace string) ImageManifestVulnInterface
}

// ImageManifestVulnInterface has methods to work with ImageManifestVuln resources.
type ImageManifestVulnInterface interface {
	Create(*v1alpha1.ImageManifestVuln) (*v1alpha1.ImageManifestVuln, error)
	Update(*v1alpha1.ImageManifestVuln) (*v1alpha1.ImageManifestVuln, error)
	UpdateStatus(*v1alpha1.ImageManifestVuln) (*v1alpha1.ImageManifestVuln, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.ImageManifestVuln, error)
	List(opts v1.ListOptions) (*v1alpha1.ImageManifestVulnList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ImageManifestVuln, err error)
	ImageManifestVulnExpansion
}

// imageManifestVulns implements ImageManifestVulnInterface
type imageManifestVulns struct {
	client rest.Interface
	ns     string
}

// newImageManifestVulns returns a ImageManifestVulns
func newImageManifestVulns(c *SecscanV1alpha1Client, namespace string) *imageManifestVulns {
	return &imageManifestVulns{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the imageManifestVuln, and returns the corresponding imageManifestVuln object, and an error if there is any.
func (c *imageManifestVulns) Get(name string, options v1.GetOptions) (result *v1alpha1.ImageManifestVuln, err error) {
	result = &v1alpha1.ImageManifestVuln{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ImageManifestVulns that match those selectors.
func (c *imageManifestVulns) List(opts v1.ListOptions) (result *v1alpha1.ImageManifestVulnList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ImageManifestVulnList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested imageManifestVulns.
func (c *imageManifestVulns) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a imageManifestVuln and creates it.  Returns the server's representation of the imageManifestVuln, and an error, if there is any.
func (c *imageManifestVulns) Create(imageManifestVuln *v1alpha1.ImageManifestVuln) (result *v1alpha1.ImageManifestVuln, err error) {
	result = &v1alpha1.ImageManifestVuln{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		Body(imageManifestVuln).
		Do().
		Into(result)
	return
}

// Update takes the representation of a imageManifestVuln and updates it. Returns the server's representation of the imageManifestVuln, and an error, if there is any.
func (c *imageManifestVulns) Update(imageManifestVuln *v1alpha1.ImageManifestVuln) (result *v1alpha1.ImageManifestVuln, err error) {
	result = &v1alpha1.ImageManifestVuln{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		Name(imageManifestVuln.Name).
		Body(imageManifestVuln).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *imageManifestVulns) UpdateStatus(imageManifestVuln *v1alpha1.ImageManifestVuln) (result *v1alpha1.ImageManifestVuln, err error) {
	result = &v1alpha1.ImageManifestVuln{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		Name(imageManifestVuln.Name).
		SubResource("status").
		Body(imageManifestVuln).
		Do().
		Into(result)
	return
}

// Delete takes name of the imageManifestVuln and deletes it. Returns an error if one occurs.
func (c *imageManifestVulns) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *imageManifestVulns) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched imageManifestVuln.
func (c *imageManifestVulns) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.ImageManifestVuln, err error) {
	result = &v1alpha1.ImageManifestVuln{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("imagemanifestvulns").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
