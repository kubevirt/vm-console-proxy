package tests

import (
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/net/context"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"kubevirt.io/client-go/kubecli"

	port_forwarder "github.com/kubevirt/vm-console-proxy/tests/port-forwarder"
)

const (
	testNamespace = "vm-console-proxy-functests"
)

var (
	ApiClient     kubecli.KubevirtClient
	PortForwarder port_forwarder.Forwarder
)

var _ = BeforeSuite(func() {
	// TODO: improve
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	Expect(err).ToNot(HaveOccurred())

	ApiClient, err = kubecli.GetKubevirtClientFromRESTConfig(config)
	Expect(err).ToNot(HaveOccurred())

	PortForwarder = port_forwarder.New(config, ApiClient.CoreV1().RESTClient())

	namespaceObj := &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	_, err = ApiClient.CoreV1().Namespaces().Create(context.TODO(), namespaceObj, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := ApiClient.CoreV1().Namespaces().Delete(context.TODO(), testNamespace, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		Expect(err).ToNot(HaveOccurred())
	}
})

func TestFunctional(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functional test suite")
}
