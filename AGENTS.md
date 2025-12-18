# Container Security Operator

Kubernetes operator that brings Quay/Clair security metadata to clusters. Watches pods, queries registries for vulnerabilities, exposes findings via `ImageManifestVuln` CRDs.

## Quick Reference

| Task | Command |
|------|---------|
| Build | `make build` |
| Run locally | `make run` |
| Install CRDs | `make installcrds` |
| Run tests | `go test -v ./...` |
| Regenerate code | `make codegen` |

## Project Structure

```
cmd/security-labeller/  # Entrypoint
labeller/               # Core controller (informers, reconciliation)
secscan/                # Registry client for vulnerability data
image/                  # Container image ID parsing
apis/secscan/v1alpha1/  # CRD types
generated/              # Auto-generated clients (do not edit)
bundle/                 # OLM deployment manifests
```

## Key Flow

1. Labeller watches Pod events via informers
2. Parses container image IDs from running pods
3. Queries registry's `.well-known/app-capabilities` endpoint
4. Fetches vulnerability data from Clair via manifest-security API
5. Creates/updates `ImageManifestVuln` resources
6. Garbage collects orphaned manifests on pod deletion

## Detailed Documentation

For specific topics, see:

- @agent_docs/architecture.md - Component details, CRD structure, configuration
- @agent_docs/development.md - Building, testing, code generation
- @agent_docs/deployment.md - OLM deployment, container builds
