package console

import (
	"fmt"
	"net/http"

	"github.com/emicklei/go-restful/v3"
)

const (
	vncPath = "/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768
)

func Run() error {
	restful.Add(webService())

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", defaultAddress, defaultPort),
	}

	return server.ListenAndServe()
}

func webService() *restful.WebService {
	ws := new(restful.WebService)
	ws.Route(ws.GET(vncPath).
		To(vncHandler).
		Doc("vnc connection").
		Operation("vnc").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)))

	return ws
}

func vncHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	// TODO -- handle error
	_ = response.WriteAsJson(struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	}{
		Name:      name,
		Namespace: namespace,
	})
}
