# API

## Generate a token

A temporary token can be generated using:
```
GET /apis/token.kubevirt.io/v1alpha1/namespaces/${VMI_NAMESPACE}/virtualmachines/${VMI_NAME}/vnc
``` 
Where `${VMI_NAMESPACE}` and `${VMI_NAME}` are the namespace
and name of a running VMI.

#### Parameters
- `duration` - Duration while the token is valid. If it is not specified, then the token will expire after 10 minutes.
  The minimum `duration` value is 10 minutes, and there isn't a maximum value.
  Its format is described in the golang library documentation [here](https://pkg.go.dev/time@go1.19.13#ParseDuration):

> A duration string is a possibly signed sequence of
> decimal numbers, each with optional fraction and a unit suffix,
> such as `300ms`, `-1.5h` or `2h45m`.
> Valid time units are `ns`, `us` (or `µs`), `ms`, `s`, `m`, `h`.

#### Result
Result is a JSON object containing the token:
```json
{ "token": "eyJhb..." }
```

### Example
```bash
curl --header "Authorization: Bearer ${KUBERNETES_USER_TOKEN}" \
     "https://${K8S_API_URL}/apis/token.kubevirt.io/v1alpha1/namespaces/${VMI_NAMESPACE}/virtualmachines/${VMI_NAME}/vnc?duration=${DURATION}"
```

In this example, we use a bearer token to authenticate the user with the Kubernetes API server.
Kubernetes supports two main ways of authentication, token and TLS client certificates.
Additional methods can be configured using the authenticating proxy. 
More information is in the [documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authentication-strategies).

If the user is logged in using a token, then the token can be retrieved using: 
```bash
KUBERNETES_USER_TOKEN=$(oc whoami -t)
```
