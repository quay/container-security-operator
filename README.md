# Container Security Operator 

The Container Security Operator (CSO) brings Quay and Clair metadata to Kubernetes / OpenShift. Starting with vulnerability information the scope will get expanded over time. If it runs on OpenShift, the corresponding vulnerability information inside the OCP Console. The Container Security Operator enables cluster administrators to monitor known container image vulnerabilites in pods running on their Kubernetes cluster. The controller sets up a watch on pods in the specified namespace(s) and queries the container registry for vulnerability information. If the container registry supports image scanning, such as [Quay](https://github.com/quay/quay) with [Clair](https://github.com/quay/clair), then the Operator will expose any vulnerabilities found via the Kubernetes API in an `ImageManifestVuln` object.  This Operator requires no additional configuration after deployment, and will begin watching pods and populating `ImageManifestVulns` immediately once installed.

## Example config

```yaml

securitylabeller:
  host: # Leave empty to use in-cluster config
  prometheusAddr: "0.0.0.0:8081"
  interval: 1m
  workers: 1
  labelPrefix: secscan # Security labels' "namespace"
  namespaces: # List of namespaces to label in the cluster
    - default
    - dev
  securityScanner:
    host: "https://quay.io"
    apiVersion: 1
    type: "Quay"
    
```

## Features

- Scan pods and store the the vulnerability information in CRs (by image manifest)
- Metrics via [Prometheus](https://prometheus.io)

## Deployment

This Operator should be deployed using the [Operator Lifecycle Manager (OLM)](https://github.com/operator-framework/operator-lifecycle-manager), which takes care of RBAC permissions, dependency resolution, and automatic upgrades.

### Kubernetes

This Operator is published upstream on [operatorhub.io](https://operatorhub.io/operator/container-security-operator).

### OpenShift

This Operator will be available via **OperatorHub**.

## Development Environment

Running the labeller locally requires a valid kubeconfig.
If the kubeconfig flag is omitted, an in-cluster config is assumed.

Running locally (using `~/.kube/config`):
```
kubectl create -f deploy/imagemanifestvuln.crd.yaml
make run
```

Regenerating clientsets, listers, and informers:
```
TODO
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
$ cd deploy/
$ docker build -t quay.io/<your-namespace>/cso-catalog .
$ docker push quay.io/<your-namespace>/cso-catalog
```
5. Change `image` field in `cso.catalogsource.yaml` to point to your image
6. Create `CatalogSource` in Kubernetes cluster w/ OLM installed
```
# Upstream Kubernetes
$ kubectl create -n olm -f deploy/cso.catalogsource.yaml
# OpenShift
$ kubectl create -n openshift-marketplace -f deploy/cso.catalogsource.yaml
```
7. After a few seconds, your Operator package should be available to create a `Subscription` to.
```
$ kubectl get packagemanifest container-security-operator
```

## Examples

### Using kubectl

List the name of the pods with a specific vulnerability:

```sh
$ kubectl get imagemanifestvuln --selector=secscan/CVE-2013-6450 -o jsonpath='{.items[*].metadata.name}'
```

List the name of the pods that has a vulnerability with severity P0:

```sh
$ kubectl get pods --selector=secscan/P0 -o jsonpath='{.items[*].metadata.name}'
```

List the name of the pods whose highest vulnerability is P1:

```sh
$ kubectl get pods --selector=secscan/highest=P1 -o jsonpath='{.items[*].metadata.name}'
```

List the name of the pods whose highest vulnerability is P1 and have P1 vulnerabilities that can be fixed:

```sh
$ kubectl get pods --selector=secscan/highest=P1,fixableP1 -o jsonpath='{.items[*].metadata.name}'
```

List all the pods that have fixable vulnerabilities

```sh
$ kubectl get pods --selector=secscan/fixables -o jsonpath='{.items[*].metadata.name}'
```
