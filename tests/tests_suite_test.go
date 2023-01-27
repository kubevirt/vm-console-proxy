package tests

import (
	"fmt"
	"net"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/net/context"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/clientcmd"
	"kubevirt.io/client-go/kubecli"

	port_forwarder "github.com/kubevirt/vm-console-proxy/tests/port-forwarder"
)

const (
	DeploymentNamespace = "kubevirt"

	apiPort = 8768

	testNamespace = "vm-console-proxy-functests"
)

var (
	ApiClient kubecli.KubevirtClient
)

var (
	portForwarder port_forwarder.Forwarder
)

var _ = BeforeSuite(func() {
	// TODO: improve
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	Expect(err).ToNot(HaveOccurred())

	ApiClient, err = kubecli.GetKubevirtClientFromRESTConfig(config)
	Expect(err).ToNot(HaveOccurred())

	portForwarder = port_forwarder.New(config, ApiClient.CoreV1().RESTClient())

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

func GetApiConnection() (net.Conn, error) {
	podList, err := ApiClient.CoreV1().Pods(DeploymentNamespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labels.Set{"vm-console-proxy.kubevirt.io": "vm-console-proxy"}.AsSelector().String(),
		FieldSelector: fields.Set{"status.phase": "Running"}.AsSelector().String(),
	})
	if err != nil {
		return nil, err
	}
	if len(podList.Items) == 0 {
		return nil, fmt.Errorf("no running pods found")
	}

	return portForwarder.Connect(&(podList.Items[0]), apiPort)
}

func TestFunctional(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functional test suite")
}
