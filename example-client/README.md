# Example VNC client

**This example client currently does not work. It will be fixed in the future.**

This directory contains an example page that uses noVNC library
to connect to the `vn-console-proxy` running on a cluster.

A simple server with this page can be started by:
```bash
make serve-client
```

The client page takes these URL parameters:
- `host` - Hostname for kubevirt API. For CRC it will be: `api.crc.testing`.
- `port` - Port for kubevirt API. For CRC it will be `6443`.
- `namspace` - Namespace where the VM is.
- `name` - Name of the VM.
- `token` - Token generated using the `/token` endpoint.

For example, the following URL will point the client to a VM after substituting variables:
```
http://localhost:8000/?host=api.crc.testing&port=6443&namespace=${VM_NAMESPACE}&name=${VM_NAME}&token=${TOKEN}
```

**Note:** If the browser does not trust the TLS certificate from the cluster, only a generic
error message will be shown, that does not contain any reason for the failure.