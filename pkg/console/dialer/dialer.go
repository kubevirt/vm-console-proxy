package dialer

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
)

type Dialer interface {
	DialVirtHandler(kubevirtClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance, tlsConfig *tls.Config) (io.ReadWriteCloser, error)
	Upgrade(responseWriter http.ResponseWriter, request *http.Request) (io.ReadWriteCloser, error)
}

func New() Dialer {
	return &dialer{}
}

type dialer struct{}

func (d *dialer) DialVirtHandler(kubevirtClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance, tlsConfig *tls.Config) (io.ReadWriteCloser, error) {
	virtHandlerConn := kubecli.NewVirtHandlerClient(kubevirtClient).Port(8186).ForNode(vmi.Status.NodeName)

	vncUri, err := virtHandlerConn.VNCURI(vmi)
	if err != nil {
		return nil, err
	}

	result, _, err := kubecli.Dial(vncUri, tlsConfig)
	if err != nil {
		return nil, err
	}
	return result.UnderlyingConn(), nil
}

func (d *dialer) Upgrade(w http.ResponseWriter, r *http.Request) (io.ReadWriteCloser, error) {
	upgrader := kubecli.NewUpgrader()
	upgrader.HandshakeTimeout = 10 * time.Second
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return conn.UnderlyingConn(), nil
}
