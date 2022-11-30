package console

import (
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kubevirt.io/client-go/kubecli"
)

const (
	vncPath = "/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768
)

func Run() error {
	cli, err := kubecli.GetKubevirtClient()
	if err != nil {
		return err
	}

	s := service{kubevirtClient: cli}
	restful.Add(s.webService())

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", defaultAddress, defaultPort),
	}

	return server.ListenAndServe()
}

type service struct {
	kubevirtClient kubecli.KubevirtClient
}

func (s *service) webService() *restful.WebService {
	ws := new(restful.WebService)
	ws.Route(ws.GET(vncPath).
		To(s.vncHandler).
		Doc("vnc connection").
		Operation("vnc").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)))

	return ws
}

func (s *service) vncHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	vm, err := s.kubevirtClient.VirtualMachineInstance(namespace).Get(name, &metav1.GetOptions{})
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, err)
		return
	}

	_ = response.WriteAsJson(vm)
}
