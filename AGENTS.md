# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

VM Console Proxy is a Kubernetes API extension that generates time-limited tokens for accessing VNC connections to KubeVirt VirtualMachines. Despite its name, it no longer provides VNC proxy functionality itself - it only handles token generation.

The service implements the `token.kubevirt.io/v1` API group and registers as a Kubernetes APIService, allowing clients to request tokens via the standard Kubernetes API server.

## Documentation

- **`docs/api.md`**: User-facing API documentation covering how to generate tokens, API parameters (duration), response format, example curl commands, and token revocation procedures.

## Architecture

### Token Generation Flow

1. **Request Reception**: Client requests token via `/apis/token.kubevirt.io/v1/namespaces/{namespace}/virtualmachines/{name}/vnc`
2. **Authentication**: User identity extracted from request headers (configured via Kubernetes extension-apiserver-authentication ConfigMap)
3. **Authorization**: RBAC check verifies user has `get` permission on `virtualmachineinstances/vnc` subresource
4. **Resource Creation**: Creates ServiceAccount, Role, and RoleBinding for the VirtualMachine (owned by VM, auto-deleted when VM is deleted)
5. **Token Request**: Generates time-limited ServiceAccount token using Kubernetes TokenRequest API
6. **Response**: Returns JWT token with expiration timestamp

### Key Components

**`pkg/console/console.go`**: Main entry point that:
- Sets up dual HTTP servers (HTTPS on 8768 for API, HTTP on 8769 for probes)
- Configures dynamic TLS using `GetConfigForClient` callback
- Registers RESTful routes for Kubernetes API discovery and token endpoint
- Manages graceful shutdown on SIGTERM/SIGINT

**`pkg/console/service/service.go`**: Core business logic:
- `TokenHandler`: Main request handler implementing the token generation flow
- `createOrUpdate`: Generic helper for idempotent resource creation with retry-on-conflict
- RBAC authorization via SubjectAccessReview
- User/group extraction from configurable HTTP headers

**`pkg/console/authConfig/authConfig.go`**: Authentication configuration reader:
- Watches `kube-system/extension-apiserver-authentication` ConfigMap
- Provides header names for user identity, groups, and extra attributes
- Supplies client CA for mTLS verification
- Uses SharedInformer for efficient ConfigMap monitoring

**`pkg/console/tlsconfig/tlsconfig.go`**: Dynamic TLS configuration:
- Watches filesystem for changes to TLS profile and certificates
- Reloads cipher suites and min TLS version from `/config/tls-profile-v1.yaml`
- Reloads certificates from `/tmp/vm-console-proxy-cert/tls.{crt,key}`
- Thread-safe configuration updates via RWMutex

**`pkg/filewatch/filewatch.go`**: Filesystem watcher abstraction wrapping fsnotify

### API Resources

The service implements these Kubernetes API endpoints:
- `GET /apis/token.kubevirt.io/v1/namespaces/{ns}/virtualmachines/{name}/vnc` - Generate token
- `GET /apis/token.kubevirt.io/v1` - List API resources
- `GET /apis/token.kubevirt.io` - Get API group info
- `GET /apis` - List API groups
- `GET /` - Root paths
- `GET /openapi/v2` - OpenAPI specification

### Generated Code

OpenAPI definitions are generated using `openapi-gen`:
- Input: `api/v1/types.go` (with `+k8s:openapi-gen=true` markers)
- Output: `pkg/generated/api/v1/zz_generated.openapi.go`
- Run `make generate` after modifying API types

### Testing

**Unit Tests**: Located alongside source files (`*_test.go`), use standard Go testing

**Functional Tests**: In `tests/` directory, use Ginkgo/Gomega:
- `api_extension_test.go`: Kubernetes API registration tests
- `proxy_test.go`: Token generation and validation
- `tlsconfig_test.go`: TLS configuration loading
- `user-role_test.go`: RBAC integration

Functional tests require `KUBECONFIG` environment variable pointing to a cluster with KubeVirt installed.

## Deployment Architecture

Kubernetes manifests in `manifests/`:
- APIService registration for aggregated API server
- Deployment with single console container
- ServiceAccount with ClusterRole for Kubernetes API access
- Service exposing HTTPS endpoint
- ConfigMap for TLS profile configuration
- User-facing ClusterRole `token.kubevirt.io:generate` for token generation permission

The Deployment uses a single container:
- Container: console (port 8768 HTTPS, 8769 HTTP probes)

## Token Lifecycle

Tokens are Kubernetes ServiceAccount tokens with owner reference to the VirtualMachine, ensuring automatic cleanup when VM is deleted. See `docs/api.md` for details on token expiration, duration configuration, and revocation procedures.

## Development Commands

### Building and Testing

```bash
# Build the binary locally
make build

# Run unit tests
make test

# Run functional tests (requires a running Kubernetes cluster)
make functest

# Format code
make fmt

# Run go vet
make vet

# Generate OpenAPI specifications
make generate
```

### Container Management

```bash
# Build multi-arch container images (amd64, s390x, arm64)
make build-container

# Push container manifest to registry
make push-container

# Set custom image repository and tag
IMG_REPOSITORY=quay.io/myorg/vm-console-proxy IMG_TAG=dev make build-container
```

### Deployment

```bash
# Deploy to cluster (uses oc/kubectl)
make deploy

# Undeploy from cluster
make undeploy

# Generate release manifests
make release-manifests
```

### Example Client

```bash
# Download and serve the noVNC example client
make serve-client
```

## Release Process

Releases are automated via GitHub Actions:
1. Create GitHub release with tag
2. Workflow builds multi-arch container images and pushes to quay.io/kubevirt/vm-console-proxy
3. Generates release manifests with tagged version
4. Uploads manifests to release assets
5. Triggers kubevirt/ssp-operator with new version
