# VM Console Proxy

This project adds a new API extension to Kubernetes, 
that can be used to generate time limited tokens to access VNC.

**Note:** This project no longer provides VNC proxy functionality, so the project name should be changed in the future.

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
