# API

## Generate a token

A temporary token can be generated using:
```
GET /apis/token.kubevirt.io/v1alpha1/namespaces/${VMI_NAMESPACE}/virtualmachines/${VMI_NAME}/vnc
``` 
Where `${VMI_NAMESPACE}` and `${VMI_NAME}` are the namespace
and name of a running VMI.

#### Parameters
- `duration` - Duration while the token is valid

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

The `KUBERNETES_USER_TOKEN` variable is a bearer token used to authenticate with
kubernetes API. It can be obtained using:
```bash
KUBERNETES_USER_TOKEN=$(oc whoami -t)
```
