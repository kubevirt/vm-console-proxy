package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/emicklei/go-restful/v3"
	"github.com/golang/mock/gomock"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	v1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	api "github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	"github.com/kubevirt/vm-console-proxy/pkg/console/authConfig"
	fakeAuth "github.com/kubevirt/vm-console-proxy/pkg/console/authConfig/fake"
)

var _ = Describe("Service", func() {

	const (
		testNamespace = "test-namespace"
		testName      = "test-name"
		testToken     = "test-token-value"
	)

	var (
		testVm *v1.VirtualMachine

		apiClient   *fake.Clientset
		virtClient  *kubecli.MockKubevirtClient
		vmInterface *kubecli.MockVirtualMachineInterface

		fakeAuthConfig *fakeAuth.FakeReader

		testService Service

		request  *restful.Request
		response *restful.Response
		recorder *httptest.ResponseRecorder

		testExpirationTimestamp metav1.Time
	)

	BeforeEach(func() {
		apiClient = fake.NewSimpleClientset()

		ctrl := gomock.NewController(GinkgoT())
		virtClient = kubecli.NewMockKubevirtClient(ctrl)
		virtClient.EXPECT().AuthenticationV1().Return(apiClient.AuthenticationV1()).AnyTimes()
		virtClient.EXPECT().AuthorizationV1().Return(apiClient.AuthorizationV1()).AnyTimes()
		virtClient.EXPECT().CoreV1().Return(apiClient.CoreV1()).AnyTimes()
		virtClient.EXPECT().RbacV1().Return(apiClient.RbacV1()).AnyTimes()

		testVm = &v1.VirtualMachine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      testName,
				Namespace: testNamespace,
			},
			Spec: v1.VirtualMachineSpec{},
		}

		vmInterface = kubecli.NewMockVirtualMachineInterface(ctrl)
		vmInterface.EXPECT().Get(gomock.Any(), testName, gomock.Any()).DoAndReturn(
			func(_ any, _ string, _ any) (*v1.VirtualMachine, error) {
				if testVm != nil {
					return testVm, nil
				}
				return nil, errors.NewNotFound(v1.Resource("virtualmachines"), testName)
			},
		).AnyTimes()

		virtClient.EXPECT().VirtualMachine(testNamespace).Return(vmInterface).AnyTimes()

		fakeAuthConfig = fakeAuth.NewFakeReader()
		testService = NewService(virtClient, fakeAuthConfig)

		request = restful.NewRequest(&http.Request{
			Header: make(http.Header),
		})
		request.PathParameters()["namespace"] = testNamespace
		request.PathParameters()["name"] = testName

		recorder = httptest.NewRecorder()
		response = restful.NewResponse(recorder)
		response.SetRequestAccepts(restful.MIME_JSON)

		apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			sar := createAction.GetObject().(*authzv1.SubjectAccessReview)
			sar.Status.Allowed = true
			return true, sar, nil
		})

		testExpirationTimestamp = metav1.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)

		apiClient.Fake.PrependReactor("create", "serviceaccounts/token", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			tokenRequest := createAction.GetObject().(*authnv1.TokenRequest)
			tokenRequest.Status.Token = testToken
			tokenRequest.Status.ExpirationTimestamp = testExpirationTimestamp

			return true, tokenRequest, nil
		})

		request.Request.Header.Set(authConfig.DefaultUserHeader, "test-user")
		request.Request.Header.Set(authConfig.DefaultGroupHeader, "test-group")

		// Using a dummy URL, so tests don't panic
		requestUrl, err := url.Parse("example.org/api")
		Expect(err).ToNot(HaveOccurred())
		request.Request.URL = requestUrl
	})

	It("should fail if namespace is empty", func() {
		delete(request.PathParameters(), "namespace")

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		Expect(recorder.Body.String()).To(ContainSubstring("namespace and name parameters are required"))
	})

	It("should fail if name is empty", func() {
		delete(request.PathParameters(), "name")

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusBadRequest))
		Expect(recorder.Body.String()).To(ContainSubstring("namespace and name parameters are required"))
	})

	It("should fail if no username header is provided", func() {
		request.Request.Header.Del(authConfig.DefaultUserHeader)

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should fail if no group header is provided", func() {
		request.Request.Header.Del(authConfig.DefaultGroupHeader)

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should pass user, group and extras to the SubjectAccessReview request", func() {
		const (
			username = "some-user"
			group    = "some-group"

			extraDataOldKey = "Data-Old"
			extraDataOld    = "data-old-value"
			extraDataNewKey = "Data-New"
			extraDataNew    = "data-new-value"
		)

		request.Request.Header.Set(authConfig.DefaultUserHeader, username)
		request.Request.Header.Set(authConfig.DefaultGroupHeader, group)
		request.Request.Header.Set(authConfig.DefaultExtraHeaderPrefix+extraDataOldKey, extraDataOld)
		request.Request.Header.Set(authConfig.DefaultExtraHeaderPrefix+extraDataNewKey, extraDataNew)

		apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			sar := createAction.GetObject().(*authzv1.SubjectAccessReview)

			Expect(sar.Spec.User).To(Equal(username))
			Expect(sar.Spec.Groups).To(ContainElement(group))
			Expect(sar.Spec.Extra).To(HaveKeyWithValue(extraDataOldKey, authzv1.ExtraValue{extraDataOld}))
			Expect(sar.Spec.Extra).To(HaveKeyWithValue(extraDataNewKey, authzv1.ExtraValue{extraDataNew}))

			sar.Status.Allowed = true
			return true, sar, nil
		})

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusOK))
	})

	It("should read header keys from auth-config", func() {
		const (
			username = "some-user"
			group    = "some-group"

			testUserHeader        = "Test-User-Header"
			testGroupHeader       = "Test-Group-Header"
			testExtraHeaderPrefix = "Test-Extra-Header-"

			extraDataOldKey = "Data-Old"
			extraDataOld    = "data-old-value"
			extraDataNewKey = "Data-New"
			extraDataNew    = "data-new-value"
		)

		fakeAuthConfig.GetUserHeadersFunc = func() ([]string, error) {
			return []string{testUserHeader}, nil
		}
		fakeAuthConfig.GetGroupHeadersFunc = func() ([]string, error) {
			return []string{testGroupHeader}, nil
		}
		fakeAuthConfig.GetExtraHeaderPrefixesFunc = func() ([]string, error) {
			return []string{testExtraHeaderPrefix}, nil
		}

		request.Request.Header = http.Header{}
		request.Request.Header.Set(testUserHeader, username)
		request.Request.Header.Set(testGroupHeader, group)
		request.Request.Header.Set(testExtraHeaderPrefix+extraDataOldKey, extraDataOld)
		request.Request.Header.Set(testExtraHeaderPrefix+extraDataNewKey, extraDataNew)

		apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			sar := createAction.GetObject().(*authzv1.SubjectAccessReview)

			Expect(sar.Spec.User).To(Equal(username))
			Expect(sar.Spec.Groups).To(ContainElement(group))
			Expect(sar.Spec.Extra).To(HaveKeyWithValue(extraDataOldKey, authzv1.ExtraValue{extraDataOld}))
			Expect(sar.Spec.Extra).To(HaveKeyWithValue(extraDataNewKey, authzv1.ExtraValue{extraDataNew}))

			sar.Status.Allowed = true
			return true, sar, nil
		})

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusOK))
	})

	It("should fail if auth config returns error", func() {
		fakeAuthConfig.GetUserHeadersFunc = func() ([]string, error) {
			return nil, fmt.Errorf("error getting user headers")
		}

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should fail if user does not have permission to access virtualmachineinstances/vnc", func() {
		apiClient.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			sar := createAction.GetObject().(*authzv1.SubjectAccessReview)
			sar.Status.Allowed = false
			return true, sar, nil
		})

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
		Expect(recorder.Body.String()).To(BeEmpty())
	})

	It("should fail if VM does not exist", func() {
		testVm = nil

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusNotFound))
		Expect(recorder.Body.String()).To(ContainSubstring("VirtualMachine does not exist"))
	})

	It("should return token", func() {
		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusOK))

		tokenResponse := &api.TokenResponse{}
		Expect(json.NewDecoder(recorder.Body).Decode(tokenResponse)).To(Succeed())

		Expect(tokenResponse.Token).To(Equal(testToken))
		Expect(&tokenResponse.ExpirationTimestamp).To(Satisfy(testExpirationTimestamp.Equal))
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
		apiClient.Fake.PrependReactor("create", "serviceaccounts/token", func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			tokenRequest := createAction.GetObject().(*authnv1.TokenRequest)
			Expect(*tokenRequest.Spec.ExpirationSeconds).To(Equal(int64(24 * 3600)))

			tokenRequest.Status.Token = testToken
			return true, tokenRequest, nil
		})

		urlWithDuration, err := url.Parse("example.org/api?duration=24h")
		Expect(err).ToNot(HaveOccurred())
		request.Request.URL = urlWithDuration

		testService.TokenHandler(request, response)

		Expect(recorder.Code).To(Equal(http.StatusOK))

		tokenResponse := &api.TokenResponse{}
		Expect(json.NewDecoder(recorder.Body).Decode(tokenResponse)).To(Succeed())
		Expect(tokenResponse.Token).To(Equal(testToken))
	})

	It("should create resources", func() {
		const resourceName = testName + "-vnc-access"

		testService.TokenHandler(request, response)
		Expect(recorder.Code).To(Equal(http.StatusOK))

		_, err := apiClient.CoreV1().ServiceAccounts(testNamespace).Get(context.Background(), resourceName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())

		_, err = apiClient.RbacV1().Roles(testNamespace).Get(context.Background(), resourceName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())

		_, err = apiClient.RbacV1().RoleBindings(testNamespace).Get(context.Background(), resourceName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())
	})
})

func TestConsole(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Console Suite")
}
