# Container annotation operator
Kubernetes Pod Security Scanner

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
- 

## Development Environment
Running the labeller locally requires a valid kubeconfig.
If the kubeconfig flag is omitted, an in-cluster config is assumed.

Running locally (using `~/.kube/config`):
```
kubectl create -f deploy/imagemanifestvuln.yaml
make run
```

Regenerating clientsets, listers, and informers:
```
TODO
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
