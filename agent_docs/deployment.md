# Deployment

## Container Image Build

```bash
# Build operator image
docker build -t quay.io/<namespace>/container-security-operator .

# Push to registry
docker push quay.io/<namespace>/container-security-operator
```

The Dockerfile uses multi-stage build:
1. Go builder stage compiles the binary
2. Alpine runtime stage with ca-certificates

## Quick Deploy (Development)

```bash
# Build and push operator image
./hack/build.sh

# Deploy to cluster
./hack/deploy.sh

# Tear down
./hack/teardown.sh
```

## OLM Deployment (Production)

The operator is deployed via Operator Lifecycle Manager.

### Bundle Contents

```
bundle/
├── imagemanifestvuln.crd.yaml      # CRD definition
├── manifests/
│   └── container-security-operator.v*.clusterserviceversion.yaml
├── metadata/
├── cso.catalogsource.yaml          # CatalogSource
├── cso.operatorgroup.yaml          # OperatorGroup
├── cso.subscription.yaml           # Subscription
└── Dockerfile                       # Catalog image build
```

### Deploy Steps

1. Update image reference in ClusterServiceVersion:
   ```yaml
   # bundle/manifests/container-security-operator.v1.0.0.clusterserviceversion.yaml
   image: quay.io/<namespace>/container-security-operator
   ```

2. Build and push catalog image:
   ```bash
   cd bundle/
   docker build -t quay.io/<namespace>/cso-catalog .
   docker push quay.io/<namespace>/cso-catalog
   ```

3. Update CatalogSource image:
   ```yaml
   # bundle/cso.catalogsource.yaml
   image: quay.io/<namespace>/cso-catalog
   ```

4. Create CatalogSource:
   ```bash
   # Upstream Kubernetes
   kubectl create -n olm -f bundle/cso.catalogsource.yaml

   # OpenShift
   kubectl create -n openshift-marketplace -f bundle/cso.catalogsource.yaml
   ```

5. Verify package is available:
   ```bash
   kubectl get packagemanifest container-security-operator
   ```

6. Create OperatorGroup and Subscription:
   ```bash
   kubectl create -n <namespace> -f bundle/cso.operatorgroup.yaml
   kubectl create -n <namespace> -f bundle/cso.subscription.yaml
   ```

## Public Availability

- **Kubernetes**: [operatorhub.io/operator/container-security-operator](https://operatorhub.io/operator/container-security-operator)
- **OpenShift**: Available via OperatorHub in the console
