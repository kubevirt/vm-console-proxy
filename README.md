# VM Console Proxy

This project adds a new API extension to Kubernetes, 
that can be used to generate time limited tokens to access VNC.

**Note:** Despite its name, this project does not proxy the VNC traffic itself. It provides the token part of a
VNC proxy solution: clients use the generated tokens to connect to the `/vnc` subresource of a KubeVirt
`VirtualMachineInstance` through the Kubernetes API.

## Why is it needed?

Accessing the VNC console of a VM through the Kubernetes API requires credentials that are allowed to `get`
the `virtualmachineinstances/vnc` subresource. For one-off access by an administrator or a VM owner, their own
credentials are enough, for example with `virtctl vnc`.

It becomes a problem when a user wants to hand VNC access over to another client, for example the browser based
VNC client of a web console or a self-service portal. The client would need the user's own Kubernetes credentials,
and with them everything the user is allowed to do in the cluster.

With this project, the user can request a token for VNC access to the VM instead. Besides `get` on
`virtualmachineinstances/vnc` for that VM, this needs a separate permission to call the token API: `get` on
`virtualmachines/vnc` in the `token.kubevirt.io` API group (see [API Access Permissions](#api-access-permissions)).
The token belongs to a ServiceAccount that is only granted VNC access to that VM. The requested duration defaults to
10 minutes, but Kubernetes can issue the token with a shorter lifetime, so clients should rely on the
`expirationTimestamp` returned with the token.

## When to use it

Use this project when VNC access to a VM should be given to another client, without sharing your own credentials
with it.

If you only need to access the console of a VM yourself, use `virtctl vnc`
(or `virtctl vnc --proxy-only` to connect with your own VNC viewer) instead.

## Demo
[![asciicast](https://asciinema.org/a/oqA9yNAteTcUxU3vyWTDWG7dh.svg)](https://asciinema.org/a/oqA9yNAteTcUxU3vyWTDWG7dh)

## Installation

### With SSP operator
The [SSP operator](https://github.com/kubevirt/ssp-operator) can be configured to install the VM Console Proxy together with
a Route to expose it to the external network.

### Without SSP operator
To deploy the latest version, use the following command:
```bash
kubectl apply -f "https://github.com/kubevirt/vm-console-proxy/releases/latest/download/vm-console-proxy.yaml"
```

## API
See the [API documentation](docs/api.md).

### API Access Permissions

The `token.kubevirt.io:generate` `ClusterRole` can be bound to users or service accounts to give
them permission to call the API.

Here are example commands how to bind it to a user or a service account:
```bash
# Bind ClusterRole to a user
kubectl create rolebinding "${ROLE_BINDING_NAME}" --clusterrole="token.kubevirt.io:generate" --user="${USER_NAME}"

# Bind ClusterRole to a ServiceAccount
kubectl create rolebinding "${ROLE_BINDING_NAME}" --clusterrole="token.kubevirt.io:generate" --serviceaccount="${SERVICE_ACCOUNT_NAME}"
```

## Development
To develop locally, set the environment variables `IMG_REPOSITORY` and `IMG_TAG` (or the variable `IMG`) to your development repository. Then run `make build-container push-container` to build the current code and push it into your development repository. Finally, run `make deploy` to install the development version.

## Dependency updates

Dependabot keeps its scheduled Go module and GitHub Actions version updates on
`main`. Renovate runs daily at 06:00 UTC and can also be started from the
Actions tab. It proposes vulnerability fixes on `main` and `release-vX.Y`
branches, but does not open routine version update PRs. Renovate uses
Dependabot alerts and OSV advisories; OSV alerts cover direct dependencies.

The Renovate workflow requires a GitHub App installed on this repository with
`contents:write`, `pull-requests:write`, `issues:write`, `workflows:write`, and
`dependabot-alerts:read` permissions. Configure its App ID and private key as
the `RENOVATE_APP_ID` and `RENOVATE_APP_PRIVATE_KEY` Actions secrets. Keep this
workflow as the only Renovate scheduler to avoid duplicate PRs.

Renovate runs `go mod tidy` for Go module updates and refreshes the tracked
root and API vendor trees for supported updates. Major Go module upgrades may
need manual vendoring. Review generated API code when a security fix changes
its inputs. The Go version report workflow comments when a Renovate PR changes
`go` or `toolchain` directives in `go.mod` or `go.work` files.
