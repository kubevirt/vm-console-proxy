package console

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	"github.com/kubevirt/vm-console-proxy/pkg/console/service"
	"github.com/kubevirt/vm-console-proxy/pkg/console/tlsconfig"
	"github.com/kubevirt/vm-console-proxy/pkg/filewatch"
)

const (
	urlPathPrefix = "api/v1alpha1/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768

	serviceCertDir = "/tmp/vm-console-proxy-cert"
	certName       = "tls.crt"
	keyName        = "tls.key"

	configDir      = "/config"
	TlsProfileFile = "tls-profile-v1alpha1.yaml"
)

func Run() error {
	cli, err := kubecli.GetKubevirtClient()
	if err != nil {
		return err
	}

	watch := filewatch.New()

	tlsConfigWatch := tlsconfig.NewWatch(
		configDir, TlsProfileFile,
		serviceCertDir, certName, keyName,
	)
	tlsConfigWatch.Reload()

	if err := tlsConfigWatch.AddToFilewatch(watch); err != nil {
		return err
	}

	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		if err := watch.Run(watchDone); err != nil {
			log.Log.Errorf("Error running file watch: %s", err)
		}
	}()

	handlers := service.NewService(cli)

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

func webService(handlers service.Service) *restful.WebService {
	ws := new(restful.WebService)
	ws.Route(ws.GET(urlPathPrefix + "/token").
		To(handlers.TokenHandler).
		Doc("generate token").
		Operation("token").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)).
		Param(ws.QueryParameter("duration", "duration")))

	return ws
}
