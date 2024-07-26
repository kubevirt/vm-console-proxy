package console

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	api "github.com/kubevirt/vm-console-proxy/api/v1"
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
	TlsProfileFile = "tls-profile-v1.yaml"
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

	ws.Route(ws.GET("/apis/" + api.Group + "/" + api.Version + "/namespaces/{namespace:[a-z0-9][a-z0-9\\-]*}/virtualmachines/{name:[a-z0-9][a-z0-9\\-]*}/vnc").
		To(handlers.TokenHandler).
		Doc("generate token").
		Operation("token").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)).
		Param(ws.QueryParameter("duration", "duration")))

	// This endpoint is called by the API Server to get available resources.
	ws.Route(ws.GET("/apis/"+api.Group+"/"+api.Version).
		Produces(restful.MIME_JSON).Writes(metav1.APIResourceList{}).
		To(func(request *restful.Request, response *restful.Response) {
			list := &metav1.APIResourceList{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIResourceList",
					APIVersion: "v1",
				},
				GroupVersion: api.Group + "/" + api.Version,
				APIResources: []metav1.APIResource{{
					Name:       "virtualmachines/vnc",
					Namespaced: true,
				}},
			}
			response.WriteAsJson(list)
		}).
		Operation("getAPIResources").
		Doc("Get API resources").
		Returns(http.StatusOK, "OK", metav1.APIResourceList{}).
		Returns(http.StatusNotFound, "NotFound", ""))

	gv := metav1.GroupVersionForDiscovery{
		GroupVersion: api.Group + "/" + api.Version,
		Version:      api.Version,
	}

	apiGroup := metav1.APIGroup{
		TypeMeta: metav1.TypeMeta{
			Kind:       "APIGroup",
			APIVersion: "v1",
		},
		Name:             api.Group,
		Versions:         []metav1.GroupVersionForDiscovery{gv},
		PreferredVersion: gv,
	}

	// K8s needs the ability to query info about a specific API group
	ws.Route(ws.GET("/apis/"+api.Group).
		Produces(restful.MIME_JSON).Writes(metav1.APIGroup{}).
		To(func(request *restful.Request, response *restful.Response) {
			response.WriteAsJson(apiGroup)
		}).
		Operation("GetSubAPIGroup").
		Doc("Get API Group").
		Returns(http.StatusOK, "OK", metav1.APIGroup{}).
		Returns(http.StatusNotFound, "NotFound", ""))

	// K8s needs the ability to query the list of API groups this endpoint supports
	ws.Route(ws.GET("apis").
		Produces(restful.MIME_JSON).Writes(metav1.APIGroupList{}).
		To(func(request *restful.Request, response *restful.Response) {
			list := &metav1.APIGroupList{
				TypeMeta: metav1.TypeMeta{
					Kind:       "APIGroupList",
					APIVersion: "v1",
				},
				Groups: []metav1.APIGroup{apiGroup},
			}
			response.WriteAsJson(list)
		}).
		Operation("getAPIGroupList").
		Doc("Get API GroupList").
		Returns(http.StatusOK, "OK", metav1.APIGroupList{}).
		Returns(http.StatusNotFound, "NotFound", ""))

	// K8s needs the ability to query the root paths
	ws.Route(ws.GET("/").
		Produces(restful.MIME_JSON).Writes(metav1.RootPaths{}).
		To(func(request *restful.Request, response *restful.Response) {
			response.WriteAsJson(&metav1.RootPaths{
				Paths: []string{
					"/apis",
					"/apis/" + api.Group,
					"/apis/" + api.Group + "/" + api.Version,
				},
			})
		}).
		Operation("getRootPaths").
		Doc("Get API root paths").
		Returns(http.StatusOK, "OK", metav1.RootPaths{}))

	return ws
}
