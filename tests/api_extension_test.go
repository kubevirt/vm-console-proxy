package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authnv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kube-openapi/pkg/validation/spec"

	api "kubevirt.io/vm-console-proxy/api/v1"
)

var _ = Describe("API extension", func() {
	// This test case checks fix for bug: https://issues.redhat.com/browse/CNV-32267
	It("should be able to delete a namespace", func() {
		testNamespace := &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-namespace-",
			},
		}

		testNamespace, err := ApiClient.CoreV1().Namespaces().Create(context.TODO(), testNamespace, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		Expect(ApiClient.CoreV1().Namespaces().Delete(context.TODO(), testNamespace.Name, metav1.DeleteOptions{})).To(Succeed())

		// The namespace should be deleted
		Eventually(func() metav1.StatusReason {
			_, err := ApiClient.CoreV1().Namespaces().Get(context.TODO(), testNamespace.Name, metav1.GetOptions{})
			return errors.ReasonForError(err)
		}, time.Minute, time.Second).
			Should(Equal(metav1.StatusReasonNotFound))
	})

	// This test case checks fix for bug: https://issues.redhat.com/browse/CNV-59744
	It("should include token.kubevirt.io/v1 in openapi/v2 response", func() {
		tokenRequest := &authnv1.TokenRequest{}
		tokenRequest, err := ApiClient.CoreV1().ServiceAccounts(testNamespace).CreateToken(context.TODO(), serviceAccountName, tokenRequest, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		saToken := tokenRequest.Status.Token

		code, body, err := httpGet(GetOpenApiEndpoint(), saToken, TestHttpClient)
		Expect(err).ToNot(HaveOccurred())
		Expect(code).To(Equal(http.StatusOK))

		openApiSpec := &spec.Swagger{}
		Expect(json.Unmarshal(body, openApiSpec)).To(Succeed())

		Expect(openApiSpec.Paths).ToNot(BeNil())
		expectedPath := "/apis/" + api.Group + "/" + api.Version + "/namespaces/{namespace}/virtualmachines/{name}/vnc"
		Expect(openApiSpec.Paths.Paths).To(HaveKey(expectedPath))
	})
})
