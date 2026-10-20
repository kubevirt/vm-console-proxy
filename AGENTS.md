# AGENTS.md

## Strict Rules

- Never modify `pkg/generated/` by hand — run `make generate` after changing `api/v1/` types
- Run `make fmt vet test` before pushing

## Architecture

Kubernetes API extension that mints time-limited VNC access tokens for VMs.

| Package | Role                                                                                                      |
|---|-----------------------------------------------------------------------------------------------------------|
| `api/v1` | Public API types and group/version constants                                                              |
| `pkg/generated` | Auto-generated OpenAPI definitions from `api/v1` types                                                    |
| `pkg/console` | Entry point: HTTPS server, health probe, route registration, file-watch hot-reload                        |
| `pkg/console/service` | `TokenHandler` - RBAC check via SubjectAccessReview, per VM SA/Role/RoleBinding creation, token minting   |
| `pkg/console/authConfig` | Watches `kube-system/extension-apiserver-authentication` ConfigMap for request-header names and client CA |
| `pkg/console/tlsconfig` | Loads server cert and TLS profile from disk, assembles TLS config, reloads via filewatch callbacks        |
| `pkg/filewatch` | Generic fsnotify wrapper - maps paths to callbacks, fires on file changes                                 |

API details: [docs/api.md](docs/api.md)

## Build and Development

Local dev deploy: see [README.md](README.md#development).

## Cluster setup

vm-console-proxy installs into the `kubevirt` namespace, which the manifest does not create. Create the namespace if it is missing (`kubectl create namespace kubevirt`). A KubeVirt install usually provides it already.

Deploy from a release:

```bash
kubectl apply -f "https://github.com/kubevirt/vm-console-proxy/releases/latest/download/vm-console-proxy.yaml"
```

Verify:

```bash
kubectl get deployment vm-console-proxy -n kubevirt
kubectl get apiservice v1.token.kubevirt.io
```

`APIService` should report `Available=True`.

## Testing

Set `KUBECONFIG` to the target cluster.

```bash
make test      # unit tests, no cluster
make functest  # requires KubeVirt, vm-console-proxy deployed in kubevirt namespace
```
