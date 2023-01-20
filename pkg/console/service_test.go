package console

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	fakemeta "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	api "github.com/akrejcir/vm-console-proxy/api/v1alpha1"
	"github.com/akrejcir/vm-console-proxy/pkg/console/dialer"
	"github.com/akrejcir/vm-console-proxy/pkg/token"
)

var _ = Describe("Service tests", func() {

	const (
		testNamespace = "test-namespace"
		testName      = "test-name"
		testUid       = "test-uid"
	)

	var (
		testVmi *v1.VirtualMachineInstance

		apiClient      *fake.Clientset
		metadataClient *fakemeta.FakeMetadataClient
		virtClient     *kubecli.MockKubevirtClient
		vmiInterface   *kubecli.MockVirtualMachineInstanceInterface

		testDialer *fakeDialer

		testService *service

		request  *restful.Request
		response *restful.Response
		recorder *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		Expect(fake.AddToScheme(scheme)).To(Succeed())

		apiClient = fake.NewSimpleClientset()
		metadataClient = fakemeta.NewSimpleMetadataClient(scheme)

		ctrl := gomock.NewController(GinkgoT())
		virtClient = kubecli.NewMockKubevirtClient(ctrl)
		virtClient.EXPECT().AuthenticationV1().Return(apiClient.AuthenticationV1()).AnyTimes()
		virtClient.EXPECT().AuthorizationV1().Return(apiClient.AuthorizationV1()).AnyTimes()

		testVmi = &v1.VirtualMachineInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testName,
				Namespace: testNamespace,
				UID:       testUid,
			},
			Status: v1.VirtualMachineInstanceStatus{
				Phase: v1.Running,
			},
		}

		metadataClient.Fake.PrependReactor("get", "virtualmachineinstances", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if testVmi == nil {
				return false, nil, nil
			}

			getAction := action.(k8stesting.GetAction)
			if getAction.GetNamespace() != testNamespace || getAction.GetName() != testName {
				return false, nil, nil
			}

			partialMeta := &metav1.PartialObjectMetadata{
				TypeMeta: metav1.TypeMeta{
					APIVersion: v1.GroupVersion.String(),
					Kind:       "VirtualMachineInstance",
				},
				ObjectMeta: testVmi.ObjectMeta,
			}
			return true, partialMeta, nil
		})

		vmiInterface = kubecli.NewMockVirtualMachineInstanceInterface(ctrl)
		vmiInterface.EXPECT().Get(testName, gomock.Any()).DoAndReturn(
			func(_ string, _ any) (*v1.VirtualMachineInstance, error) {
				if testVmi != nil {
					return testVmi, nil
				}
				return nil, errors.NewNotFound(v1.Resource("virtualmachineinstances"), testName)
			},
		).AnyTimes()

		virtClient.EXPECT().VirtualMachineInstance(testNamespace).Return(vmiInterface).AnyTimes()

		testDialer = &fakeDialer{
			DialVirtHandlerFunc: func(_ kubecli.KubevirtClient, _ *v1.VirtualMachineInstance, _ *tls.Config) (io.ReadWriteCloser, error) {
				panic("DialVirtHandler function not implemented")
			},
			UpgradeFunc: func(_ http.ResponseWriter, _ *http.Request) (io.ReadWriteCloser, error) {
				panic("Upgrade function not defined")
			},
		}

		testService = &service{
			kubevirtClient:  virtClient,
			metadataClient:  metadataClient,
			websocketDialer: testDialer,
			tokenSigningKey: []byte("testing-key"),
		}

		request = restful.NewRequest(&http.Request{
			Header: make(http.Header),
		})
		request.PathParameters()["namespace"] = testNamespace
		request.PathParameters()["name"] = testName

		recorder = httptest.NewRecorder()
		response = restful.NewResponse(recorder)
		response.SetRequestAccepts(restful.MIME_JSON)
	})

	Context("TokenHandler", func() {
		const authorizationHeader = "Authorization"

		BeforeEach(func() {
			const validToken = "test-auth-token"
			apiClient.Fake.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				tokenReview := createAction.GetObject().(*authnv1.TokenReview)
				tokenReview.Status.Authenticated = true
				return true, tokenReview, nil
			})

			apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				sar := createAction.GetObject().(*authzv1.SubjectAccessReview)
				sar.Status.Allowed = true
				return true, sar, nil
			})

			request.Request.Header.Set(authorizationHeader, "Bearer "+validToken)
			// Using a dummy URL, so tests don't panic
			requestUrl, err := url.Parse("example.org/api")
			Expect(err).ToNot(HaveOccurred())
			request.Request.URL = requestUrl
		})

		It("should fail if no Authorization header is provided", func() {
			request.Request.Header.Del(authorizationHeader)

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("authenticating token cannot be empty"))
		})

		It("should fail if Authorization header is not Bearer", func() {
			request.Request.Header.Set(authorizationHeader, "Unknown auth header format")

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("authenticating token cannot be empty"))
		})

		It("should fail if authorization token is invalid", func() {
			apiClient.Fake.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				tokenReview := createAction.GetObject().(*authnv1.TokenReview)
				tokenReview.Status.Authenticated = false
				return true, tokenReview, nil
			})

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("token is not authenticated"))
		})

		It("should fail if authorization token does not have permission to access virtualmachineinstances/vnc", func() {
			apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				sar := createAction.GetObject().(*authzv1.SubjectAccessReview)
				sar.Status.Allowed = false
				return true, sar, nil
			})

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(ContainSubstring("does not have permission to access virtualmachineinstances/vnc endpoint"))
		})

		It("should pass user info from TokenReview to SubjectAccessReview", func() {
			const (
				userName = "user-name"
				userUid  = "user-uid"
			)

			var (
				groups = []string{"group1", "group2"}
			)

			apiClient.Fake.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				tokenReview := createAction.GetObject().(*authnv1.TokenReview)
				tokenReview.Status.Authenticated = true
				tokenReview.Status.User = authnv1.UserInfo{
					Username: userName,
					UID:      userUid,
					Groups:   groups,
				}
				return true, tokenReview, nil
			})

			apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				createAction := action.(k8stesting.CreateAction)
				sar := createAction.GetObject().(*authzv1.SubjectAccessReview)

				Expect(sar.Spec.User).To(Equal(userName))
				Expect(sar.Spec.UID).To(Equal(userUid))
				Expect(sar.Spec.Groups).To(Equal(groups))

				sar.Status.Allowed = true
				return true, sar, nil
			})

			testService.TokenHandler(request, response)
		})

		It("should fail if VMI does not exist", func() {
			testVmi = nil

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusNotFound))
			Expect(recorder.Body.String()).To(ContainSubstring("VirtualMachineInstance does no exist"))
		})

		It("should return token", func() {
			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusOK))

			tokenResponse := &api.TokenResponse{}
			Expect(json.NewDecoder(recorder.Body).Decode(tokenResponse)).To(Succeed())

			claims := &token.Claims{}
			_, _, err := jwt.NewParser().ParseUnverified(tokenResponse.Token, claims)
			Expect(err).ToNot(HaveOccurred())

			Expect(claims.Name).To(Equal(testName))
			Expect(claims.Namespace).To(Equal(testNamespace))
			Expect(claims.UID).To(Equal(testUid))
		})

		It("should fail if duration parameter fails to parse", func() {
			urlWithDuration, err := url.Parse("example.org/api?duration=this-fails-to-parse")
			Expect(err).ToNot(HaveOccurred())
			request.Request.URL = urlWithDuration

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusBadRequest))
			Expect(recorder.Body.String()).To(ContainSubstring("failed to parse duration"))
		})

		It("should return token with specified duration", func() {
			urlWithDuration, err := url.Parse("example.org/api?duration=24h")
			Expect(err).ToNot(HaveOccurred())
			request.Request.URL = urlWithDuration

			testService.TokenHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusOK))

			tokenResponse := &api.TokenResponse{}
			Expect(json.NewDecoder(recorder.Body).Decode(tokenResponse)).To(Succeed())

			claims := &token.Claims{}
			_, _, err = jwt.NewParser().ParseUnverified(tokenResponse.Token, claims)
			Expect(err).ToNot(HaveOccurred())

			expireTime := claims.ExpiresAt.Time
			expectedTime := time.Now().Add(24 * time.Hour)

			// Comparing time difference, because it will not be exactly
			// the same.
			Expect(expireTime.Sub(expectedTime).Abs()).
				To(BeNumerically("<=", 5*time.Second))
		})
	})

	Context("VncHandler", func() {
		const subprotocolHeader = "Sec-Websocket-Protocol"

		BeforeEach(func() {
			claims := &token.Claims{
				Name:      testName,
				Namespace: testNamespace,
				UID:       testUid,
			}
			validToken, err := token.NewSignedToken(claims, testService.tokenSigningKey)
			Expect(err).ToNot(HaveOccurred())

			request.Request.Header.Set(subprotocolHeader, "base64url.bearer.authorization.k8s.io."+validToken)
		})

		It("should fail if no token is provided", func() {
			request.Request.Header.Del(subprotocolHeader)

			testService.VncHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("request is not authenticated"))
		})

		It("should fail if token is invalid", func() {
			// Sign token with a different key to make it invalid
			invalidToken, err := token.NewSignedToken(&token.Claims{}, []byte("different-token"))
			Expect(err).ToNot(HaveOccurred())

			request.Request.Header.Set(subprotocolHeader, "base64url.bearer.authorization.k8s.io."+invalidToken)

			testService.VncHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("request is not authenticated"))
		})

		It("should fail if VMI does not exist", func() {
			testVmi = nil

			testService.VncHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusNotFound))
			Expect(recorder.Body.String()).To(ContainSubstring("VirtualMachineInstance does no exist"))
		})

		It("should fail if VMI is not running", func() {
			testVmi.Status.Phase = v1.Succeeded

			testService.VncHandler(request, response)

			Expect(recorder.Code).To(Equal(http.StatusNotFound))
			Expect(recorder.Body.String()).To(ContainSubstring("is not running"))
		})

		It("should proxy connection", func() {
			serverTestSide, serverHandlerSide := newDuplexPipe()
			testDialer.DialVirtHandlerFunc = func(_ kubecli.KubevirtClient, _ *v1.VirtualMachineInstance, _ *tls.Config) (io.ReadWriteCloser, error) {
				return serverHandlerSide, nil
			}

			clientTestSide, clientHandlerSide := newDuplexPipe()
			testDialer.UpgradeFunc = func(_ http.ResponseWriter, _ *http.Request) (io.ReadWriteCloser, error) {
				return clientHandlerSide, nil
			}

			handlerFinished := make(chan struct{})
			go func() {
				defer GinkgoRecover()
				defer close(handlerFinished)
				testService.VncHandler(request, response)
			}()

			const messageFromClient = "message-from-client"
			_, err := io.WriteString(clientTestSide, messageFromClient)
			Expect(err).ToNot(HaveOccurred())

			readBuff := make([]byte, len([]byte(messageFromClient)))
			_, err = io.ReadFull(serverTestSide, readBuff)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(readBuff)).To(Equal(messageFromClient))

			const messageFromServer = "message-from-server"
			_, err = io.WriteString(serverTestSide, messageFromServer)
			Expect(err).ToNot(HaveOccurred())

			readBuff = make([]byte, len([]byte(messageFromServer)))
			_, err = io.ReadFull(clientTestSide, readBuff)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(readBuff)).To(Equal(messageFromServer))

			Expect(clientTestSide.Close()).To(Succeed())
			Expect(serverTestSide.Close()).To(Succeed())

			Eventually(handlerFinished, time.Second).Should(BeClosed())
		})
	})
})

type fakeDialer struct {
	DialVirtHandlerFunc func(kubevirtClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance, tlsConfig *tls.Config) (io.ReadWriteCloser, error)
	UpgradeFunc         func(responseWriter http.ResponseWriter, request *http.Request) (io.ReadWriteCloser, error)
}

var _ dialer.Dialer = &fakeDialer{}

func (f *fakeDialer) DialVirtHandler(kubevirtClient kubecli.KubevirtClient, vmi *v1.VirtualMachineInstance, tlsConfig *tls.Config) (io.ReadWriteCloser, error) {
	return f.DialVirtHandlerFunc(kubevirtClient, vmi, tlsConfig)
}

func (f *fakeDialer) Upgrade(responseWriter http.ResponseWriter, request *http.Request) (io.ReadWriteCloser, error) {
	return f.UpgradeFunc(responseWriter, request)
}

type duplexPipe struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

var _ io.ReadWriteCloser = &duplexPipe{}

func (d *duplexPipe) Read(p []byte) (n int, err error) {
	return d.reader.Read(p)
}

func (d *duplexPipe) Write(p []byte) (n int, err error) {
	return d.writer.Write(p)
}

func (d *duplexPipe) Close() error {
	return d.writer.Close()
}

func newDuplexPipe() (*duplexPipe, *duplexPipe) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	pipe1 := &duplexPipe{reader: r1, writer: w2}
	pipe2 := &duplexPipe{reader: r2, writer: w1}
	return pipe1, pipe2
}

func TestConsole(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Console Suite")
}
