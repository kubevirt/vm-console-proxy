# Example VNC client

This directory contains an example page that uses noVNC library
to connect to the `vn-console-proxy` running on a cluster.

A simple server with this page can be started by:
```bash
make serve-client
```

The client page takes these URL parameters:
- `host` - Hostname for the route. For CRC it will be: `vm-console-kubevirt.apps-crc.testing`
- `namspace` - Namespace where the VM is.
- `name` - Name of the VM.
- `token` - Token generated using the `/token` endpoint.

For example, the following URL will point the client to a VM after substituting variables:
```
http://localhost:8000/?host=vm-console-kubevirt.apps-crc.testing&namespace=${VM_NAMESPACE}&name=${VM_NAME}&token=${TOKEN}
```