package console

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	api "github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	"github.com/kubevirt/vm-console-proxy/pkg/console/authConfig"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	"github.com/kubevirt/vm-console-proxy/pkg/console/service"
	"github.com/kubevirt/vm-console-proxy/pkg/console/tlsconfig"
	"github.com/kubevirt/vm-console-proxy/pkg/filewatch"
)

const (
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

	authConfigReader, err := authConfig.CreateReader(cli.CoreV1().RESTClient())
	if err != nil {
		return err
	}
	defer authConfigReader.Stop()

	watch := filewatch.New()

	tlsConfigWatch := tlsconfig.NewWatch(
		configDir, TlsProfileFile,
		serviceCertDir, certName, keyName,
		authConfigReader,
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

	handlers := service.NewService(cli, authConfigReader)

	restful.Add(webService(handlers))
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

	ws.Path("/apis/" + api.Group + "/" + api.Version)

	ws.Route(ws.GET("/namespaces/{namespace:[a-z0-9][a-z0-9\\-]*}/virtualmachines/{name:[a-z0-9][a-z0-9\\-]*}/vnc").
		To(handlers.TokenHandler).
		Doc("generate token").
		Operation("token").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)).
		Param(ws.QueryParameter("duration", "duration")))

	// This endpoint is called by the API Server to get available resources.
	// We can return an empty list here, it does not block the functionality.
	ws.Route(ws.GET("/").
		To(func(request *restful.Request, response *restful.Response) {
			list := &metav1.APIResourceList{
				TypeMeta: metav1.TypeMeta{
					Kind: "APIResourceList",
				},
				APIResources: []metav1.APIResource{},
			}
			response.WriteAsJson(list)
		}))

	return ws
}
