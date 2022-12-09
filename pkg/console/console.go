package console

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/util/cert"
	kubevirtcore "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	"github.com/akrejcir/vm-console-proxy/pkg/token"
)

const (
	urlPathPrefix = "/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

	defaultAddress = "0.0.0.0"
	defaultPort    = 8768

	serviceCertPath = "/tmp/vm-console-proxy-cert/tls.crt"
	serviceKeyPath  = "/tmp/vm-console-proxy-cert/tls.key"

	virtHandlerCertPath = "/etc/virt-handler/clientcertificates/tls.crt"
	virtHandlerKeyPath  = "/etc/virt-handler/clientcertificates/tls.key"
)

func Run() error {
	cli, err := kubecli.GetKubevirtClient()
	if err != nil {
		return err
	}

	serviceCert, err := loadCertificates(serviceCertPath, serviceKeyPath)
	if err != nil {
		return err
	}

	tokenKey, err := token.CreateHmacKey(serviceCert.PrivateKey)
	if err != nil {
		return err
	}

	s := service{
		kubevirtClient:  cli,
		tokenSigningKey: tokenKey,
	}

	restful.Add(s.webService())
	cors := restful.CrossOriginResourceSharing{
		AllowedHeaders: []string{"Authorization"},
	}
	restful.Filter(cors.Filter)
	restful.Filter(restful.OPTIONSFilter())

	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", defaultAddress, defaultPort),
	}

	return server.ListenAndServe()
}

type service struct {
	kubevirtClient kubecli.KubevirtClient

	// TODO: Needs to be refreshed when secret changes
	tokenSigningKey []byte
}

func (s *service) webService() *restful.WebService {
	ws := new(restful.WebService)
	ws.Route(ws.GET(urlPathPrefix + "/token").
		To(s.tokenHandler).
		Doc("generate token").
		Operation("token").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)))

	ws.Route(ws.GET(urlPathPrefix + "/vnc").
		To(s.vncHandler).
		Doc("vnc connection").
		Operation("vnc").
		Param(ws.PathParameter("namespace", "namespace").Required(true)).
		Param(ws.PathParameter("name", "name").Required(true)))

	return ws
}

func (s *service) tokenHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	// TODO: test RBAC access to the /vnc endpoint of VMI

	// TODO: optimize by only getting metadata
	vmi, err := s.kubevirtClient.VirtualMachineInstance(namespace).Get(name, &metav1.GetOptions{})
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error getting VirtualMachineInstance: %w", err))
		return
	}

	claims := &token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			// TODO: Add expiration
			ExpiresAt: nil,
		},
		Name:      name,
		Namespace: namespace,
		UID:       string(vmi.UID),
	}

	signedToken, err := token.NewSignedToken(claims, s.tokenSigningKey)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error signing token: %w", err))
		return
	}

	_ = response.WriteAsJson(struct {
		Token string `json:"token"`
	}{
		Token: signedToken,
	})
}

func (s *service) vncHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	authHeader := request.HeaderParameter("Authorization")
	if !s.authJwt(authHeader, name, namespace) {
		_ = response.WriteErrorString(http.StatusUnauthorized, "request is not authenticated")
		return
	}

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

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadCertificates(virtHandlerCertPath, virtHandlerKeyPath)
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

func (s *service) authJwt(authHeader string, vmiName, vmiNamespace string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}

	jwtToken := authHeader[len(prefix):]
	claims, err := token.ParseToken(jwtToken, s.tokenSigningKey)
	if err != nil {
		return false
	}

	if claims.Name != vmiName || claims.Namespace != vmiNamespace {
		return false
	}

	// TODO: Optimize by only getting metadata
	// TODO: Optimize by not getting VMI twice
	vmi, err := s.kubevirtClient.VirtualMachineInstance(vmiNamespace).Get(vmiName, &metav1.GetOptions{})
	if err != nil {
		return false
	}

	if claims.UID != string(vmi.UID) {
		return false
	}

	return true
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
