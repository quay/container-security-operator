# Container Security Operator 

The Container Security Operator (CSO) brings Quay and Clair metadata to Kubernetes / OpenShift. Starting with vulnerability information the scope will get expanded over time. If it runs on OpenShift, the corresponding vulnerability information can be visualized inside the OCP Console. The Container Security Operator enables cluster administrators to monitor known container image vulnerabilites in pods running on their Kubernetes cluster. The controller sets up a watch on pods in the specified namespace(s) and queries the container registry for vulnerability information. If the container registry supports image scanning, such as [Quay](https://github.com/quay/quay) with [Clair](https://github.com/quay/clair), then the Operator will expose any vulnerabilities found via the Kubernetes API in an `ImageManifestVuln` object.  This Operator requires no additional configuration after deployment, and will begin watching pods and populating `ImageManifestVulns` immediately once installed.

## ImageManifestVuln
The security information of scanned images are stored in `ImageManifestVulns` on an image manifest basis, and are named by the image's manifest digest.

### Spec
The spec provides information about the features and its associated vulnarabilities.
The spec should be immutable relative to the cluster. When a new vulnerability is added to a feature, the operator will update the spec after the resync threshold.

### Status
The status provides information about the affected Pods/Containers. As pod are added or removed
from the cluster, their references are added to the `affectedPods` field of the status block.
The status also provide various statistics about the manifest. e.g lastUpdate, highestSeverity, ...

### Label Selectors
TODO

## Example config
```yaml
securitylabeller:
  prometheusAddr: "0.0.0.0:8081"
  interval: 15m
  wellknownEndpoint: ".well-known/app-capabilities"
  labelPrefix: secscan
  namespaces:
    - default
    - dev
```

The same options can be configured from the command line:
```
./container-security-operator -promAddr ":8081" -resyncInterval "15m" -wellknownEndpoint ".well-known/app-capabilities" -labelPrefix "secscan" -namespace default -namespace test
```

## Deployment

This Operator should be deployed using the [Operator Lifecycle Manager (OLM)](https://github.com/operator-framework/operator-lifecycle-manager), which takes care of RBAC permissions, dependency resolution, and automatic upgrades.

The fastest way to get started is by deploying the operator in an OCP cluster using the setup scripts provided in the hack directory:

```
./hack/build.sh
./hack/deploy.sh
```

### Kubernetes

This Operator is published upstream on [operatorhub.io](https://operatorhub.io/operator/container-security-operator).

### OpenShift

This Operator will be available via **OperatorHub**.

## Development Environment

Running the labeller locally requires a valid kubeconfig.
If the kubeconfig flag is omitted, an in-cluster config is assumed.

Install the ImageManifestVuln CRD
```
make installcrds
```

Running locally (using `~/.kube/config` and `example-config.yaml`):
```
make run
```

To regenerate the CRD code:
```
# deepcopy
make deepcopy
# openapi
make openapi
# clientset
make clientset
# listers
make listers
# informers
make informers
# generate all
codegen
# generate all in a container
codegen-container
```

### Deploying using OLM

Follow these steps to package and deploy the Operator from local source code using OLM:

1. Make any code changes to the source code
2. Build and push Operator container image
```
$ docker build -t quay.io/<your-namespace>/container-security-operator .
$ docker push quay.io/<your-namespace>/container-security-operator
```
3. Change `image` field in `container-security-operator.v1.0.0.clusterserviceversion.yaml` to point to your image
4. Build and push `CatalogSource` container image
```
$ cd bundle/
$ docker build -t quay.io/<your-namespace>/cso-catalog .
$ docker push quay.io/<your-namespace>/cso-catalog
```
5. Change `image` field in `cso.catalogsource.yaml` to point to your image
6. Create `CatalogSource` in Kubernetes cluster w/ OLM installed
```
# Upstream Kubernetes
$ kubectl create -n olm -f bundle/cso.catalogsource.yaml
# OpenShift
$ kubectl create -n openshift-marketplace -f bundle/cso.catalogsource.yaml
```
7. After a few seconds, your Operator package should be available to create a `Subscription` to.
```
$ kubectl get packagemanifest container-security-operator
```
8. Create `OperatorGroup`:
```
$ kubectl create -n <your-namespace> -f ./bundle/cso.operatorgroup.yaml
```
9. Create the `Subscription` to install the Operator. Make sure name of the `CatalogSource` is same as source of `Subscription`:
```
$ kubectl create -n <your-namespace> -f ./bundle/cso.subscription.yaml
```

## Examples

### Using kubectl

Get a list of all the pods affected by vulnerable images detected by the Operator:
```sh
$ kubectl get imagemanifestvuln --all-namespaces -o json | jq '.items[].status.affectedPods' | jq 'keys' | jq 'unique'
```

Get a list of all detected CVEs in pods running on the cluster:
```sh
$ kubectl get imagemanifestvuln --all-namespaces -o json | jq '[.items[].spec.features[].vulnerabilities[].name'] | jq 'unique'
```

Check if a pod has any vulnerability, and list the CVEs, if any:
```sh
$ kubectl get imagemanifestvulns.secscan.quay.redhat.com --selector=<namespace>/<pod-name> -o jsonpath='{.items[*].spec.features[*].vulnerabilities[*].name}'
```
