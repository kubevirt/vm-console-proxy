# VM Console Proxy

Proxy that provides access to the VNC console of a Kubevirt VM.

It can generate time limited tokens that are then used to access VNC.

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
  namespace: kubevirt
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
