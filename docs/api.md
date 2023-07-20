# API

The commands in this document use environment variable `PROXY_URL`,
which should be set to the URL where the `vm-console-proxy` service is
exposed to the outside of the cluster.

## Generate a token

A temporary token can be generated using:
```
GET /api/v1alpha1/${VMI_NAMESPACE}/${VMI_NAME}/token
``` 
Where `${VMI_NAMESPACE}` and `${VMI_NAME}` are the namespace
and name of a running VMI.

#### Parameters
- `duration` - Duration while the token is valid

#### Headers
- `Authorization` - Contains Bearer token that is used to check
  RBAC permissions to access `/vnc` subresource on a VMI

#### Result
Result is a JSON object containing the token:
```json
{ "token": "eyJhb..." }
```

### Example
```bash
curl --header "Authorization: Bearer ${KUBERNETES_USER_TOKEN}" \
     "https://${PROXY_URL}/api/v1alpha1/${VMI_NAMESPACE}/${VMI_NAME}/token?duration=${DURATION}"
```

The `KUBERNETES_USER_TOKEN` variable is a bearer token used to authenticate with
kubernetes API. It can be obtained using:
```bash
KUBERNETES_USER_TOKEN=$(oc whoami -t)
```
