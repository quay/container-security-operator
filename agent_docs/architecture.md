# Architecture

## Components

### cmd/security-labeller/main.go
Entrypoint that:
- Parses CLI flags and config file
- Handles TLS certificate configuration
- Creates and runs the Labeller controller

### labeller/
Core controller implementation:
- `labeller.go`: Main controller with informers for Pods and ImageManifestVulns, work queue, reconciliation logic
- `manifest.go`: ImageManifestVuln creation/update, garbage collection, affected pod tracking
- `config.go`: Configuration struct and YAML loading
- `multinamespacelistwatcher.go`: Watches resources across multiple namespaces

### secscan/
Registry client for vulnerability scanning:
- `client.go`: Main client interface implementation
- `wellknown.go`: Fetches `.well-known/app-capabilities` from registries
- `types.go`: Response types from Clair (Layer, Feature, Vulnerability)
- `quay/`: Quay-specific implementations
- `rest/`: HTTP REST client utilities

### image/
Container image parsing:
- `image.go`: Parses image IDs from various formats (Docker Hub, private registries, with/without digests)
- Handles pull secret parsing from Kubernetes secrets

### apis/secscan/v1alpha1/
CRD type definitions:
- `types.go`: ImageManifestVuln, Feature, Vulnerability structs
- `register.go`: Scheme registration

## ImageManifestVuln CRD

### Spec (immutable scanner data)
- `image`: Image name
- `manifest`: Manifest digest
- `features`: List of features with vulnerabilities

### Status (dynamic cluster state)
- `affectedPods`: Map of pod paths to container IDs
- Severity counts: `unknownCount`, `lowCount`, `mediumCount`, `highCount`, `criticalCount`, `defcon1Count`
- `fixableCount`: Vulnerabilities with available fixes
- `lastUpdate`: Timestamp of last resync

## Configuration

Via CLI flags or `example/example-config.yaml`:

| Option | Default | Description |
|--------|---------|-------------|
| `namespaces` | (all) | Namespaces to watch |
| `interval` | 30m | Controller resync interval |
| `resyncThreshold` | 1h | Min time before refreshing vuln data |
| `labelPrefix` | secscan | Label prefix for resources |
| `wellknownEndpoint` | .well-known/app-capabilities | Registry endpoint |
| `promAddr` | :8081 | Prometheus metrics address |
| `insecure` | false | Skip TLS verification |
| `extraCerts` | | Directory with extra CA certificates |
