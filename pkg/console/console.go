package console

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"github.com/emicklei/go-restful/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/cert"
	kubevirtcore "kubevirt.io/api/core/v1"
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

	vmi, err := s.kubevirtClient.VirtualMachineInstance(namespace).Get(name, &metav1.GetOptions{})
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error getting VirtualMachineInstance: %w", err))
		return
	}

	if !vmi.IsRunning() {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("vmi %s/%s is not running", vmi.Namespace, vmi.Name))
		return
	}

	virtHandlerConn := kubecli.NewVirtHandlerClient(s.kubevirtClient).Port(8186).ForNode(vmi.Status.NodeName)

	guestInfoUri, err := virtHandlerConn.GuestInfoURI(vmi)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("failed to get guest agent info URI: %w", err))
		return
	}

	const certPath = "/etc/virt-handler/clientcertificates/tls.crt"
	const keyPath = "/etc/virt-handler/clientcertificates/tls.key"

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadCertificates(certPath, keyPath)
		},
	}

	data, err := virtHandlerConn.Get(guestInfoUri, tlsConfig)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("virthandler get request failed: %w", err))
		return
	}

	guestAgentInfo := &kubevirtcore.VirtualMachineInstanceGuestAgentInfo{}
	if err := json.Unmarshal([]byte(data), guestAgentInfo); err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("failed to unmarshall response: %w", err))
		return
	}

	_ = response.WriteAsJson(guestAgentInfo)
}

func loadCertificates(certPath, keyPath string) (*tls.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	crt, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v\n", err)
	}
	leaf, err := cert.ParseCertsPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load leaf certificate: %v\n", err)
	}
	crt.Leaf = leaf[0]
	return &crt, nil
}
