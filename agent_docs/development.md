# Development

## Prerequisites

- Go 1.23+
- kubectl with cluster access
- Docker or Podman (for container builds)

## Building

```bash
# Build the operator binary
make build
# Output: bin/security-labeller

# Update vendored dependencies
make vendor
```

## Running Locally

```bash
# Install the CRD first
make installcrds

# Run with local kubeconfig
make run
# Uses: ~/.kube/config and example/example-config.yaml

# Or run directly with flags
./bin/security-labeller \
  -kubeconfig ~/.kube/config \
  -namespaces default,test \
  -resyncInterval 15m \
  -promAddr :8081
```

## Testing

```bash
# Run all tests
go test -v ./...

# Run specific package tests
go test -v ./labeller/...
go test -v ./image/...
go test -v ./secscan/...
go test -v ./k8sutils/...

# Run with coverage
go test -v -cover ./...
```

## Code Generation

The `generated/` directory contains auto-generated Kubernetes clients. To regenerate after modifying `apis/secscan/v1alpha1/types.go`:

```bash
# Clone code-generator (one-time setup)
make get-code-generator

# Regenerate clientsets, informers, listers
make codegen
```

This updates:
- `generated/clientset/` - Typed client for ImageManifestVuln
- `generated/informers/` - Shared informer factories
- `generated/listers/` - Indexer-backed listers
- `apis/secscan/v1alpha1/zz_generated.deepcopy.go` - DeepCopy methods

## Development Environment Setup

```bash
# Install CRD and apply example manifests
make devenv
# Runs: kubectl create -f bundle/imagemanifestvuln.crd.yaml
#       kubectl apply -f bundle/examples/
```

## CI Checks

The GitHub Actions CI runs:
1. `go mod tidy` - Verify go.mod is clean
2. `make build` - Build compiles successfully
3. `go test -v ./...` - All tests pass
