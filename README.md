# VM Console Proxy

It provides an endpoint to generate time limited tokens that are then used to access VNC.

**Note:** This project no longer provides VNC proxy functionality, so the project name should be changed in the future.

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

## Exposing the service

The `Service` is not exposed by default, because the `Ingress` configuration
can depend on the cluster where it is running. For example this `Ingress` can be used:

[//]: # (TODO: This ingress currently does not work with OpenShit. Look into why.)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: vm-console
  namespace: ${VM_CONSOLE_PROXY_NAMESPACE}
spec:
  rules:
    - host: ${HOSTNAME}
      http:
        paths:
          - backend:
              service:
                name: vm-console-proxy
                port:
                  number: 443
            path: /
            pathType: Prefix
```
