package console

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/cert"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	"github.com/akrejcir/vm-console-proxy/pkg/token"
)

const (
	urlPathPrefix = "api/v1alpha1/{namespace:[a-z0-9][a-z0-9\\-]*}/{name:[a-z0-9][a-z0-9\\-]*}"

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

	subprotocols := websocket.Subprotocols(request.Request)

	var authToken string
	const authSubprotocolPrefix = "base64url.bearer.authorization.k8s.io."
	for _, subprotocol := range subprotocols {
		if strings.HasPrefix(subprotocol, authSubprotocolPrefix) {
			authToken = subprotocol[len(authSubprotocolPrefix):]
			break
		}
	}

	if !s.authJwt(authToken, name, namespace) {
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

	vncUri, err := virtHandlerConn.VNCURI(vmi)
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

	serverConn, _, err := kubecli.Dial(vncUri, tlsConfig)
	if err != nil {
		return
	}
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("failed dial vnc: %w", err))
		return
	}

	upgrader := kubecli.NewUpgrader()
	upgrader.HandshakeTimeout = 10 * time.Second
	clientConn, err := upgrader.Upgrade(response.ResponseWriter, request.Request, nil)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("failed upgrade client connection: %w", err))
		return
	}

	ctx, cancel := context.WithCancel(request.Request.Context())
	defer cancel()
	go func() {
		<-ctx.Done()
		serverConn.Close()
		clientConn.Close()
	}()

	copyResults := make(chan error, 2)
	go func() {
		_, err := io.Copy(clientConn.UnderlyingConn(), serverConn.UnderlyingConn())
		copyResults <- err
	}()
	go func() {
		_, err := io.Copy(serverConn.UnderlyingConn(), clientConn.UnderlyingConn())
		copyResults <- err
	}()

	res1 := <-copyResults
	cancel()
	res2 := <-copyResults

	err = res1
	if err == nil {
		err = res2
	}

	// TODO: this error is always shown. Look into why.
	if err != nil {
		log.Log.Errorf("error with websocket connection: %w", err)
	}
}

func (s *service) authJwt(jwtToken string, vmiName, vmiNamespace string) bool {
	if len(jwtToken) == 0 {
		return false
	}

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
