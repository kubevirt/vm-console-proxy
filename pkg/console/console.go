package console

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/client-go/metadata"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	"github.com/kubevirt/vm-console-proxy/pkg/console/dialer"
	"github.com/kubevirt/vm-console-proxy/pkg/console/tlsconfig"
	"github.com/kubevirt/vm-console-proxy/pkg/token"
)

const (
	urlPathPrefix = "api/v1alpha1/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768

	serviceCertPath = "/tmp/vm-console-proxy-cert/tls.crt"
	serviceKeyPath  = "/tmp/vm-console-proxy-cert/tls.key"

	configDir      = "/config"
	TlsProfileFile = "tls-profile-v1alpha1.yaml"
)

func Run() error {
	cli, err := kubecli.GetKubevirtClient()
	if err != nil {
		return err
	}

	metadataClient, err := metadata.NewForConfig(cli.Config())
	if err != nil {
		return err

	}

	tlsConfigWatch := tlsconfig.NewWatch(
		filepath.Join(configDir, TlsProfileFile),
		serviceCertPath,
		serviceKeyPath,
	)
	tlsConfigWatch.Reload()

	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		err := tlsConfigWatch.Run(watchDone)
		log.Log.Errorf("Error running TLS config watch: %s", err)
	}()

	serviceCert, err := tlsconfig.LoadCertificates(serviceCertPath, serviceKeyPath)
	if err != nil {
		return err
	}

	tokenKey, err := token.CreateHmacKey(serviceCert.PrivateKey)
	if err != nil {
		return err
	}

	handlers := &service{
		kubevirtClient:  cli,
		metadataClient:  metadataClient,
		websocketDialer: dialer.New(),
		tokenSigningKey: tokenKey,
	}

	restful.Add(webService(handlers))
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Authorization"},
	}
	restful.Filter(cors.Filter)
	restful.Filter(restful.OPTIONSFilter())

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", defaultAddress, defaultPort),
		TLSConfig: &tls.Config{
			GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
				return tlsConfigWatch.GetConfig()
			},
			GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// This function is not called, but it needs to be non-nil, otherwise
				// the server tries to load certificate from filenames passed to
				// ListenAndServe().
				panic("function should not be called")
			},
		},
	}

	return server.ListenAndServeTLS("", "")
}

func webService(handlers *service) *restful.WebService {
	ws := new(restful.WebService)
	ws.Route(ws.GET(urlPathPrefix + "/token").
		To(handlers.TokenHandler).
		Doc("generate token").
		Operation("token").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)).
		Param(ws.QueryParameter("duration", "duration")))

	ws.Route(ws.GET(urlPathPrefix + "/vnc").
		To(handlers.VncHandler).
		Doc("vnc connection").
		Operation("vnc").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)))

	return ws
}
