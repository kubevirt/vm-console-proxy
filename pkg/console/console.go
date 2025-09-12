package console

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/emicklei/go-restful/v3"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kube-openapi/pkg/builder"
	"k8s.io/kube-openapi/pkg/common"
	"k8s.io/kube-openapi/pkg/common/restfuladapter"
	"k8s.io/kube-openapi/pkg/validation/spec"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	api "kubevirt.io/vm-console-proxy/api/v1"
	"kubevirt.io/vm-console-proxy/pkg/console/authConfig"
	"kubevirt.io/vm-console-proxy/pkg/console/service"
	"kubevirt.io/vm-console-proxy/pkg/console/tlsconfig"
	"kubevirt.io/vm-console-proxy/pkg/filewatch"
	generated "kubevirt.io/vm-console-proxy/pkg/generated/api/v1"
)

const (
	defaultAddress = "0.0.0.0"
	defaultPort    = 8768
	probePort      = 8769

	serviceCertDir = "/tmp/vm-console-proxy-cert"
	certName       = "tls.crt"
	keyName        = "tls.key"

	configDir      = "/config"
	TlsProfileFile = "tls-profile-v1.yaml"
)

func Run() error {
	log.InitializeLogging("vm-console-proxy")
	log.Log.Info("Starting VM Console Proxy")

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

	handlers := service.NewService(cli, authConfigReader)

	ws, err := webService(handlers)
	if err != nil {
		return fmt.Errorf("failed to create web service: %w", err)
	}

	restful.Add(ws)
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

	probeMux := http.NewServeMux()
	probeMux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {})

	probeServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", defaultAddress, probePort),
		Handler: probeMux,
	}

	sigCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	group, groupCtx := errgroup.WithContext(sigCtx)

	group.Go(startWatch(groupCtx, watch))
	group.Go(startServerTLS(server))
	group.Go(startServer(probeServer))
	group.Go(stopServer(groupCtx, probeServer))
	group.Go(stopServer(groupCtx, server))

	return group.Wait()
}

func startWatch(ctx context.Context, watch filewatch.Watch) func() error {
	log.Log.Info("Starting watch")
	return func() error {
		if err := watch.Run(ctx.Done()); err != nil {
			log.Log.Errorf("Error running file watch: %s", err)
			return err
		}
		return nil
	}
}

func startServer(server *http.Server) func() error {
	log.Log.Info("Starting http server")
	return func() error {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Log.Errorf("Error running http server: %s", err)
			return err
		}
		return nil
	}
}

func startServerTLS(server *http.Server) func() error {
	log.Log.Info("Starting https server")
	return func() error {
		if err := server.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			log.Log.Errorf("Error running https server: %s", err)
			return err
		}
		return nil
	}
}

func stopServer(ctx context.Context, server *http.Server) func() error {
	return func() error {
		<-ctx.Done()
		log.Log.Infof("Shutting down the http server")
		shutDownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutDownCtx)
	}
}

func webService(handlers service.Service) (*restful.WebService, error) {
	ws := new(restful.WebService)

	ws.Route(ws.GET("/apis/"+api.Group+"/"+api.Version+"/namespaces/{namespace}/virtualmachines/{name}/vnc").
		To(handlers.TokenHandler).
		Doc("generate token").
		Operation("token").
		Returns(http.StatusOK, "OK", api.TokenResponse{}).
		Returns(http.StatusBadRequest, "BadRequest", "").
		Returns(http.StatusNotFound, "NotFound", "").
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
					"/openapi/v2",
				},
			})
		}).
		Operation("getRootPaths").
		Doc("Get API root paths").
		Returns(http.StatusOK, "OK", metav1.RootPaths{}))

	openApiSpec, err := builder.BuildOpenAPISpecFromRoutes(restfuladapter.AdaptWebServices([]*restful.WebService{ws}), openApiConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to build OpenAPI spec from routes: %w", err)
	}

	ws.Route(ws.GET("openapi/v2").
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON).
		To(func(request *restful.Request, response *restful.Response) {
			response.WriteAsJson(openApiSpec)
		}))

	return ws, nil
}

func openApiConfig() *common.Config {
	return &common.Config{
		CommonResponses: map[int]spec.Response{
			401: {
				ResponseProps: spec.ResponseProps{
					Description: "Unauthorized",
				},
			},
		},
		Info: &spec.Info{
			InfoProps: spec.InfoProps{
				Title:       "KubeVirt VNC token generation API",
				Description: "This is the VNC token generation API for Kubevirt.",
				Contact: &spec.ContactInfo{
					Name:  "kubevirt-dev",
					Email: "kubevirt-dev@googlegroups.com",
					URL:   "https://github.com/kubevirt/kubevirt",
				},
				License: &spec.License{
					Name: "Apache 2.0",
					URL:  "https://www.apache.org/licenses/LICENSE-2.0",
				},
			},
		},
		SecurityDefinitions: &spec.SecurityDefinitions{
			"BearerToken": &spec.SecurityScheme{
				SecuritySchemeProps: spec.SecuritySchemeProps{
					Type:        "apiKey",
					Name:        "authorization",
					In:          "header",
					Description: "Bearer Token authentication",
				},
			},
		},
		GetDefinitions: generated.GetOpenAPIDefinitions,
	}
}
