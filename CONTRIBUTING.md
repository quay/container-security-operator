# Contributing to container-security-operator

## Setup

```bash
# Requires OpenShift cluster with Quay integration
make install
make deploy
```

## Development

Displays Clair vulnerability scan results in OpenShift console.

Watches:
- `ImageManifestVuln` CRs (created by Clair/Quay)
- Pods (to link vulns to running workloads)

## Testing

```bash
# Unit tests
make test

# E2E (requires OpenShift + Quay with Clair)
make test-e2e
```

## Pull Requests

- Test on OpenShift 4.x
- Update labeller logic tests
- Verify console UI displays correctly
- Update CRD if adding new fields

## Code Structure

- `apis/secscan/v1alpha1/` - CRD types
- `cmd/manager/` - operator entrypoint
- `labeller/` - pod vulnerability labeling
- `k8sutils/` - K8s client helpers
- `bundle/` - OLM metadata
