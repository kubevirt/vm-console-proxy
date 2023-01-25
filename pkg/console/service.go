package console

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/metadata"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"
	"kubevirt.io/client-go/log"

	"github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	"github.com/kubevirt/vm-console-proxy/pkg/console/dialer"
	"github.com/kubevirt/vm-console-proxy/pkg/token"
)

const (
	virtHandlerCertPath = "/etc/virt-handler/clientcertificates/tls.crt"
	virtHandlerKeyPath  = "/etc/virt-handler/clientcertificates/tls.key"
)

type service struct {
	kubevirtClient  kubecli.KubevirtClient
	metadataClient  metadata.Interface
	websocketDialer dialer.Dialer

	// TODO: Needs to be refreshed when secret changes
	tokenSigningKey []byte
}

func (s *service) TokenHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	authToken := getAuthToken(request)
	if authToken == "" {
		_ = response.WriteError(http.StatusUnauthorized, fmt.Errorf("authenticating token cannot be empty"))
		return
	}

	err := s.checkVncRbac(authToken, name, namespace)
	if err != nil {
		_ = response.WriteError(http.StatusUnauthorized, err)
		return
	}

	vmiMeta, err := s.metadataClient.Resource(kubevirtv1.GroupVersion.WithResource("virtualmachineinstances")).
		Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_ = response.WriteError(http.StatusNotFound, fmt.Errorf("VirtualMachineInstance does no exist: %w", err))
			return
		}
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error getting VirtualMachineInstance: %w", err))
		return
	}

	duration := 10 * time.Minute
	durationParam := request.QueryParameter("duration")
	if durationParam != "" {
		var err error
		duration, err = time.ParseDuration(durationParam)
		if err != nil {
			_ = response.WriteError(http.StatusBadRequest, fmt.Errorf("failed to parse duration: %w", err))
			return
		}
	}

	claims := &token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
		Name:      name,
		Namespace: namespace,
		UID:       string(vmiMeta.UID),
	}

	signedToken, err := token.NewSignedToken(claims, s.tokenSigningKey)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error signing token: %w", err))
		return
	}

	_ = response.WriteAsJson(&v1alpha1.TokenResponse{
		Token: signedToken,
	})
}

func (s *service) VncHandler(request *restful.Request, response *restful.Response) {
	namespace := request.PathParameter("namespace")
	name := request.PathParameter("name")

	authToken := getAuthTokenWebsocket(request)
	if len(authToken) == 0 {
		_ = response.WriteErrorString(http.StatusUnauthorized, "request is not authenticated")
		return
	}

	claims, err := token.ParseToken(authToken, s.tokenSigningKey)
	if err != nil {
		_ = response.WriteErrorString(http.StatusUnauthorized, "request is not authenticated")
		return
	}

	if claims.Name != name || claims.Namespace != namespace {
		_ = response.WriteErrorString(http.StatusUnauthorized, "request is not authenticated")
		return
	}

	vmi, err := s.kubevirtClient.VirtualMachineInstance(namespace).Get(name, &metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_ = response.WriteError(http.StatusNotFound, fmt.Errorf("VirtualMachineInstance does no exist: %w", err))
			return
		}
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("error getting VirtualMachineInstance: %w", err))
		return
	}

	if claims.UID != string(vmi.UID) {
		_ = response.WriteErrorString(http.StatusUnauthorized, "request is not authenticated")
		return
	}

	if !vmi.IsRunning() {
		_ = response.WriteError(http.StatusNotFound, fmt.Errorf("VMI %s/%s is not running", vmi.Namespace, vmi.Name))
		return
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return LoadCertificates(virtHandlerCertPath, virtHandlerKeyPath)
		},
	}

	serverConn, err := s.websocketDialer.DialVirtHandler(s.kubevirtClient, vmi, tlsConfig)
	if err != nil {
		_ = response.WriteError(http.StatusInternalServerError, fmt.Errorf("failed dial vnc: %w", err))
		return
	}

	clientConn, err := s.websocketDialer.Upgrade(response.ResponseWriter, request.Request)
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
		_, err := io.Copy(clientConn, serverConn)
		copyResults <- err
	}()
	go func() {
		_, err := io.Copy(serverConn, clientConn)
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
		log.Log.Errorf("error with websocket connection: %s", err)
	}
}

func (s *service) checkVncRbac(rbacToken string, vmiName, vmiNamespace string) error {
	tokenReview := &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token: rbacToken,
		},
	}

	tokenReview, err := s.kubevirtClient.AuthenticationV1().TokenReviews().Create(context.TODO(), tokenReview, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error authenticating token: %w", err)
	}
	if tokenReview.Status.Error != "" {
		return fmt.Errorf("error authenticating token: %s", tokenReview.Status.Error)
	}

	if !tokenReview.Status.Authenticated {
		return fmt.Errorf("token is not authenticated")
	}

	extras := map[string]authzv1.ExtraValue{}
	for key, value := range tokenReview.Status.User.Extra {
		extras[key] = authzv1.ExtraValue(value)
	}

	accessReview := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace:   vmiNamespace,
				Name:        vmiName,
				Verb:        "get",
				Group:       kubevirtv1.SubresourceGroupName,
				Version:     "v1",
				Resource:    "virtualmachineinstances",
				Subresource: "vnc",
			},
			User:   tokenReview.Status.User.Username,
			Groups: tokenReview.Status.User.Groups,
			Extra:  extras,
			UID:    tokenReview.Status.User.UID,
		},
	}

	accessReview, err = s.kubevirtClient.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), accessReview, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("error checking permissions: %w", err)
	}

	if !accessReview.Status.Allowed {
		return fmt.Errorf("does not have permission to access virtualmachineinstances/vnc endpoint: %s", accessReview.Status.Reason)
	}
	return nil
}

func getAuthToken(request *restful.Request) string {
	authHeader := request.HeaderParameter("Authorization")

	const bearerPrefix = "Bearer "
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return authHeader[len(bearerPrefix):]
	}
	return ""
}

func getAuthTokenWebsocket(request *restful.Request) string {
	subprotocols := websocket.Subprotocols(request.Request)

	const authSubprotocolPrefix = "base64url.bearer.authorization.k8s.io."
	for _, subprotocol := range subprotocols {
		if strings.HasPrefix(subprotocol, authSubprotocolPrefix) {
			return subprotocol[len(authSubprotocolPrefix):]
		}
	}
	return ""
}
