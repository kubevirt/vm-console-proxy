package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/clientcmd"
	kubevirtcorev1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	api "kubevirt.io/vm-console-proxy/api/v1"
	port_forwarder "kubevirt.io/vm-console-proxy/tests/port-forwarder"
)

const (
	DeploymentNamespace = "kubevirt"

	apiPort = 8768

	testHostname = "vm-console.test"

	configMapName = "vm-console-proxy"

	testNamespace      = "vm-console-proxy-functests"
	serviceAccountName = "vm-console-proxy-functests"
	roleName           = serviceAccountName
)

var (
	apiServerHostname string

	ApiClient         kubecli.KubevirtClient
	PortForwardClient *http.Client
	TestHttpClient    *http.Client
)

var (
	portForwarder port_forwarder.Forwarder

	originalConfigMap *core.ConfigMap
)

var _ = BeforeSuite(func() {
	// TODO: improve
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	Expect(err).ToNot(HaveOccurred())

	apiServerHostname = config.Host

	ApiClient, err = kubecli.GetKubevirtClientFromRESTConfig(config)
	Expect(err).ToNot(HaveOccurred())

	portForwarder = port_forwarder.New(config, ApiClient.CoreV1().RESTClient())

	portForwardTransport := http.DefaultTransport.(*http.Transport).Clone()
	portForwardTransport.MaxConnsPerHost = 1
	portForwardTransport.MaxIdleConnsPerHost = 1
	portForwardTransport.DialContext = PortForwardDial
	portForwardTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	PortForwardClient = &http.Client{
		Transport: portForwardTransport,
	}

	testHttpTransport := http.DefaultTransport.(*http.Transport).Clone()
	testHttpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	TestHttpClient = &http.Client{
		Transport: testHttpTransport,
	}

	originalConfigMap, err = ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
	Expect(err).ToNot(HaveOccurred())

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
			Name:      roleName,
			Namespace: testNamespace,
		},
		Rules: []rbac.PolicyRule{{
			APIGroups: []string{"token.kubevirt.io"},
			Resources: []string{"virtualmachines/vnc"},
			Verbs:     []string{"get"},
		}, {
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
			Name:      roleName,
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

	// Binding the service account to system:discovery ClusterRole, so it can access /openapi/v2 endpoint
	clusterRoleBinding := &rbac.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: roleName + "-cluster-role",
		},
		Subjects: []rbac.Subject{{
			Kind:      "ServiceAccount",
			Name:      serviceAccount.Name,
			Namespace: serviceAccount.Namespace,
		}},
		RoleRef: rbac.RoleRef{
			APIGroup: rbac.GroupName,
			Kind:     "ClusterRole",
			Name:     "system:discovery",
		},
	}
	_, err = ApiClient.RbacV1().ClusterRoleBindings().Create(context.TODO(), clusterRoleBinding, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() {
		err := ApiClient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), clusterRoleBinding.Name, metav1.DeleteOptions{})
		if err != nil && !errors.IsNotFound(err) {
			Expect(err).ToNot(HaveOccurred())
		}
	})
})

var _ = AfterSuite(func() {
	RevertToOriginalConfigMap()
})

func RevertToOriginalConfigMap() {
	Eventually(func() error {
		foundConfig, err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			newConfig := &core.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:                       originalConfigMap.Name,
					Namespace:                  originalConfigMap.Namespace,
					DeletionGracePeriodSeconds: originalConfigMap.DeletionGracePeriodSeconds,
					Labels:                     originalConfigMap.Labels,
					Annotations:                originalConfigMap.Annotations,
					OwnerReferences:            originalConfigMap.OwnerReferences,
					Finalizers:                 originalConfigMap.Finalizers,
				},
				Immutable:  originalConfigMap.Immutable,
				Data:       originalConfigMap.Data,
				BinaryData: originalConfigMap.BinaryData,
			}
			_, err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Create(context.TODO(), newConfig, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}

		foundConfig.Data = originalConfigMap.Data
		foundConfig.BinaryData = originalConfigMap.BinaryData

		_, err = ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Update(context.TODO(), foundConfig, metav1.UpdateOptions{})
		return err
	}, 10*time.Second, time.Second).Should(Succeed())
}

func UpdateConfigMap(updateFunc func(configMap *core.ConfigMap)) {
	Eventually(func() error {
		foundConfig, err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		updateFunc(foundConfig)
		_, err = ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Update(context.TODO(), foundConfig, metav1.UpdateOptions{})
		return err
	}, 10*time.Second, time.Second).Should(Succeed())
}

func GetApiUrlBase() string {
	return apiServerHostname + "/apis/" + api.Group + "/" + api.Version + "/"
}

func GetOpenApiEndpoint() string {
	return apiServerHostname + "/openapi/v2"
}

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

func httpGet(url string, authToken string, client *http.Client) (int, []byte, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, err
	}

	if authToken != "" {
		request.Header.Set("Authorization", "Bearer "+authToken)
	}

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, body, nil
}

func TestFunctional(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Functional test suite")
}
