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
