package dialer

import (
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"kubevirt.io/client-go/kubecli"
)

type Dialer interface {
	Dial(address string, tlsConfig *tls.Config) (io.ReadWriteCloser, error)
	Upgrade(responseWriter http.ResponseWriter, request *http.Request) (io.ReadWriteCloser, error)
}

func New() Dialer {
	return &dialer{}
}

type dialer struct{}

func (d *dialer) Dial(address string, tlsConfig *tls.Config) (io.ReadWriteCloser, error) {
	result, _, err := kubecli.Dial(address, tlsConfig)
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
