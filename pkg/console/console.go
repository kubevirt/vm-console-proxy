package console

import (
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	"k8s.io/client-go/metadata"
	"kubevirt.io/client-go/kubecli"

	"github.com/kubevirt/vm-console-proxy/pkg/console/dialer"
	"github.com/kubevirt/vm-console-proxy/pkg/token"
)

const (
	urlPathPrefix = "api/v1alpha1/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768

	serviceCertPath = "/tmp/vm-console-proxy-cert/tls.crt"
	serviceKeyPath  = "/tmp/vm-console-proxy-cert/tls.key"
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

	serviceCert, err := LoadCertificates(serviceCertPath, serviceKeyPath)
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
	}

	return server.ListenAndServeTLS(serviceCertPath, serviceKeyPath)
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
