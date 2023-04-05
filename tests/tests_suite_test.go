package tests

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"golang.org/x/net/context"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/clientcmd"
	kubevirtcorev1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	port_forwarder "github.com/kubevirt/vm-console-proxy/tests/port-forwarder"
)

const (
	DeploymentNamespace = "kubevirt"

	apiPort = 8768

	testHostname = "vm-console.test"

	testNamespace      = "vm-console-proxy-functests"
	serviceAccountName = "vm-console-proxy-functests"
	roleBindingName    = serviceAccountName
)

var (
	ApiClient      kubecli.KubevirtClient
	TestHttpClient *http.Client
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 1
	transport.MaxIdleConnsPerHost = 1
	transport.DialContext = PortForwardDial
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	TestHttpClient = &http.Client{
		Transport: transport,
	}

	namespaceObj := &core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
		},
	}
	_, err = ApiClient.CoreV1().Namespaces().Create(context.TODO(), namespaceObj, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := ApiClient.CoreV1().Namespaces().Delete(context.TODO(), namespaceObj.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})

	serviceAccount := &core.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: testNamespace,
		},
	}
	_, err = ApiClient.CoreV1().ServiceAccounts(testNamespace).Create(context.TODO(), serviceAccount, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := ApiClient.CoreV1().ServiceAccounts(testNamespace).Delete(context.TODO(), serviceAccount.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})

	role := &rbac.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: testNamespace,
		},
		Rules: []rbac.PolicyRule{{
			APIGroups: []string{kubevirtcorev1.SubresourceGroupName},
			Resources: []string{"virtualmachineinstances/vnc"},
			Verbs:     []string{"get"},
		}},
	}
	_, err = ApiClient.RbacV1().Roles(testNamespace).Create(context.TODO(), role, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := ApiClient.RbacV1().Roles(testNamespace).Delete(context.TODO(), role.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})

	roleBinding := &rbac.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName,
			Namespace: testNamespace,
		},
		Subjects: []rbac.Subject{{
			Kind:      "ServiceAccount",
			Name:      serviceAccount.Name,
			Namespace: serviceAccount.Namespace,
		}},
		RoleRef: rbac.RoleRef{
			APIGroup: rbac.GroupName,
			Kind:     "Role",
			Name:     role.Name,
		},
	}
	_, err = ApiClient.RbacV1().RoleBindings(testNamespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := ApiClient.RbacV1().RoleBindings(testNamespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})
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

func PortForwardDial(ctx context.Context, network, addr string) (net.Conn, error) {
	// The port-forwarding only supports TCP
	if network != "tcp" {
		return nil, fmt.Errorf("only TCP connections are supported, got: %s", network)
	}
	// This address is used to specify port-forwarding connection
	if addr != testHostname+":443" {
		return nil, fmt.Errorf("invalid address: %s", addr)
	}

	return GetApiConnection()
}

func TestFunctional(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functional test suite")
}
