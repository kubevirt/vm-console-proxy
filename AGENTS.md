# AGENTS.md

## Strict Rules

- Never modify `pkg/generated/` by hand — run `make generate` after changing `api/v1/` types
- `api/` is a separate Go module (`replace => ./api`); its sources are copied into root `vendor/`. After `api/v1/` changes: `make generate`, then `go mod vendor` at the repo root
- Never edit `vendor/` or `api/vendor/` by hand — after dependency changes in a module, run `go mod tidy && go mod vendor` in that module (root or `api/`)
- Run `make fmt vet test` before pushing; root targets skip `api/`, so when you change `api/`, also run `cd api && go fmt ./... && go vet ./...`

## Architecture

Kubernetes API extension that generates time-limited tokens for VNC access to VMs. Tokens are ServiceAccount tokens requested from the Kubernetes TokenRequest API.

| Package | Role |
|---|---|
| `api/v1` | Public API types and group/version constants |
| `pkg/generated` | Auto-generated OpenAPI definitions from `api/v1` types |
| `pkg/console` | Entry point: HTTPS server, health probe, route registration, file-watch hot-reload |
| `pkg/console/service` | `TokenHandler` - SubjectAccessReview for VMI/vnc access, per-VM SA/Role/RoleBinding, TokenRequest on `{vm}-vnc-access` |
| `pkg/console/authConfig` | Watches `kube-system/extension-apiserver-authentication` ConfigMap for request-header names and client CA |
| `pkg/console/tlsconfig` | Loads server cert and TLS profile from disk, assembles TLS config, reloads via filewatch callbacks |
| `pkg/filewatch` | Generic fsnotify wrapper - maps paths to callbacks, fires on file changes |

API details: [docs/api.md](docs/api.md)

## Build and Development

Local dev deploy: see [README.md](README.md#development).

## Cluster setup

This repo covers OpenShift. CI runs the functional tests on OpenShift (openshift/release `ci-operator/config/kubevirt/vm-console-proxy`). There is no Kubernetes install path: the manifest does not create a TLS secret or an APIService `caBundle`. It expects the OpenShift service-ca operator to create the secret `vm-console-proxy-cert` and fill in the APIService `caBundle`.

### OpenShift

If the SSP operator already deploys vm-console-proxy (see [README.md](README.md#with-ssp-operator)),
do not apply the release manifest: it replaces the cluster-wide APIService `v1.token.kubevirt.io`.

The release manifest installs into the `kubevirt` namespace and does not create it. Create the namespace if it is missing (`kubectl create namespace kubevirt`). A KubeVirt install usually provides it already.

For functional tests, install KubeVirt if it is not already there (see `automation/e2e-functests/deploy-kubevirt.sh`).

Deploy and verify: see [README.md](README.md#installation).

## Testing

```bash
make test      # unit tests, no cluster
make functest  # requires KubeVirt, vm-console-proxy deployed in kubevirt namespace
```

For `functest`, set `KUBECONFIG` to the target cluster.
