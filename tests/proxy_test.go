package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/mitchellh/go-vnc"
	authnv1 "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/pointer"
	kubevirtcorev1 "kubevirt.io/api/core/v1"
	"kubevirt.io/client-go/kubecli"

	api "github.com/akrejcir/vm-console-proxy/api/v1alpha1"
)

var _ = Describe("Token", func() {
	const (
		testHostname = "vm-console.test"
		urlBase      = testHostname + "/api/v1alpha1/"
		httpUrlBase  = "http://" + urlBase

		apiPort = 8768

		vmiName       = "vm-cirros"
		tokenEndpoint = "token"
	)

	var (
		portForwardDial func(ctx context.Context, network, addr string) (net.Conn, error)
		httpClient      *http.Client

		serviceAccount *core.ServiceAccount
		roleBinding    *rbac.RoleBinding
		saToken        string
	)

	BeforeEach(func() {
		portForwardDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			defer GinkgoRecover()
			// The port-forwarding only supports TCP
			if network != "tcp" {
				return nil, fmt.Errorf("only TCP connections are supported, got: %s", network)
			}
			// This address is used to specify port-forwarding connection
			if addr != testHostname+":80" {
				return nil, fmt.Errorf("invalid address: %s", addr)
			}

			// TODO -- namespace should be configurable
			podList, err := ApiClient.CoreV1().Pods("kubevirt").List(context.TODO(), metav1.ListOptions{
				LabelSelector: labels.Set{"vm-console-proxy.kubevirt.io": "vm-console-proxy"}.AsSelector().String(),
			})
			if err != nil {
				return nil, err
			}
			if len(podList.Items) == 0 {
				return nil, fmt.Errorf("no pods found")
			}

			return PortForwarder.Connect(&(podList.Items[0]), apiPort)
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxConnsPerHost = 1
		transport.MaxIdleConnsPerHost = 1
		transport.DialContext = portForwardDial
		httpClient = &http.Client{
			Transport: transport,
		}

		serviceAccount = &core.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-service-account-",
				Namespace:    testNamespace,
			},
		}
		serviceAccount, err := ApiClient.CoreV1().ServiceAccounts(testNamespace).Create(context.TODO(), serviceAccount, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := ApiClient.CoreV1().ServiceAccounts(testNamespace).Delete(context.TODO(), serviceAccount.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
			serviceAccount = nil
		})

		role := &rbac.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-role-",
				Namespace:    testNamespace,
			},
			Rules: []rbac.PolicyRule{{
				APIGroups: []string{kubevirtcorev1.SubresourceGroupName},
				Resources: []string{"virtualmachineinstances/vnc"},
				Verbs:     []string{"get"},
			}},
		}
		role, err = ApiClient.RbacV1().Roles(testNamespace).Create(context.TODO(), role, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := ApiClient.RbacV1().Roles(testNamespace).Delete(context.TODO(), role.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		roleBinding = &rbac.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-clusterrolebinding-",
				Namespace:    testNamespace,
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
		roleBinding, err = ApiClient.RbacV1().RoleBindings(testNamespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := ApiClient.RbacV1().RoleBindings(testNamespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
			roleBinding = nil
		})

		tokenRequest := &authnv1.TokenRequest{}
		tokenRequest, err = ApiClient.CoreV1().ServiceAccounts(testNamespace).CreateToken(context.TODO(), serviceAccount.Name, tokenRequest, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		saToken = tokenRequest.Status.Token
	})

	Context("/token endpoint", func() {
		var (
			tokenUrl string
		)

		BeforeEach(func() {
			var err error
			tokenUrl, err = url.JoinPath(httpUrlBase, testNamespace, vmiName, tokenEndpoint)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should fail if not authenticated", func() {
			code, body, err := httpGet(tokenUrl, "", httpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusUnauthorized))
			Expect(string(body)).To(ContainSubstring("authenticating token cannot be empty"))
		})

		It("should fail if not authorized to access vmi/vnc endpoint", func() {
			err := ApiClient.RbacV1().RoleBindings(roleBinding.Namespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			code, body, err := httpGet(tokenUrl, saToken, httpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusUnauthorized))
			Expect(string(body)).To(ContainSubstring("does not have permission to access virtualmachineinstances/vnc endpoint"))
		})

		It("should fail if VMI does not exist", func() {
			code, body, err := httpGet(tokenUrl, saToken, httpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusNotFound))
			Expect(string(body)).To(ContainSubstring("VirtualMachineInstance does no exist"))
		})

		Context("with running VM", func() {
			BeforeEach(func() {
				vm := testVm(vmiName)
				vm, err := ApiClient.VirtualMachine(testNamespace).Create(vm)
				Expect(err).ToNot(HaveOccurred())

				DeferCleanup(func() {
					err := ApiClient.VirtualMachine(testNamespace).Delete(vm.Name, &metav1.DeleteOptions{})
					if err != nil && !errors.IsNotFound(err) {
						Expect(err).ToNot(HaveOccurred())
					}
					Eventually(func() bool {
						_, err := ApiClient.VirtualMachineInstance(vm.Namespace).Get(vm.Name, &metav1.GetOptions{})
						return errors.IsNotFound(err)
					}, time.Minute, time.Second).Should(BeTrue())
				})

				Eventually(func() error {
					_, err := ApiClient.VirtualMachineInstance(vm.Namespace).Get(vm.Name, &metav1.GetOptions{})
					return err
				}, time.Minute, time.Second).Should(Succeed())
			})

			It("should get token with default duration", func() {
				code, body, err := httpGet(tokenUrl, saToken, httpClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(code).To(Equal(http.StatusOK))

				tokenResponse := &api.TokenResponse{}
				Expect(json.Unmarshal(body, tokenResponse)).To(Succeed())
				Expect(tokenResponse.Token).ToNot(BeEmpty())
			})

			It("should get token with specified duration", func() {
				tokenUrl, err := url.JoinPath(httpUrlBase, testNamespace, vmiName, tokenEndpoint)
				Expect(err).ToNot(HaveOccurred())

				code, body, err := httpGet(tokenUrl+"?duration=24h", saToken, httpClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(code).To(Equal(http.StatusOK))

				tokenResponse := &api.TokenResponse{}
				Expect(json.Unmarshal(body, tokenResponse)).To(Succeed())
				Expect(tokenResponse.Token).ToNot(BeEmpty())

				claims := &jwt.RegisteredClaims{}
				_, _, err = jwt.NewParser().ParseUnverified(tokenResponse.Token, claims)
				Expect(err).ToNot(HaveOccurred())

				expireTime := claims.ExpiresAt.Time
				expectedTime := time.Now().Add(24 * time.Hour)

				// Comparing time difference, because it will not be exactly the same.
				Expect(expireTime.Sub(expectedTime).Abs()).
					To(BeNumerically("<=", 5*time.Second))
			})
		})
	})

	Context("/vnc endpoint", func() {
		const (
			wssUrlBase  = "ws://" + urlBase
			vncEndpoint = "vnc"

			subprotocolPrefix = "base64url.bearer.authorization.k8s.io."
		)

		var (
			vncUrl string
			dialer *websocket.Dialer
		)

		BeforeEach(func() {
			var err error
			vncUrl, err = url.JoinPath(wssUrlBase, testNamespace, vmiName, vncEndpoint)
			Expect(err).ToNot(HaveOccurred())

			dialer = &websocket.Dialer{
				NetDialContext: portForwardDial,
			}
		})

		It("should fail if no token is provided", func() {
			conn, response, err := dialer.Dial(vncUrl, nil)
			if conn != nil {
				_ = conn.Close()
				Fail("Websocket connection should not succeed.")
			}
			Expect(err).To(MatchError(websocket.ErrBadHandshake))

			Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
			Expect(io.ReadAll(response.Body)).To(ContainSubstring("request is not authenticated"))
		})

		It("should fail if token is invalid", func() {
			conn, response, err := dialer.Dial(vncUrl, nil)
			if conn != nil {
				_ = conn.Close()
				Fail("Websocket connection should not succeed.")
			}
			Expect(err).To(MatchError(websocket.ErrBadHandshake))

			Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
			Expect(io.ReadAll(response.Body)).To(ContainSubstring("request is not authenticated"))
		})

		Context("with VMI", func() {
			var (
				vm       *kubevirtcorev1.VirtualMachine
				vncToken string
			)

			BeforeEach(func() {
				// Create and start VM
				vm = testVm(vmiName)
				vm, err := ApiClient.VirtualMachine(testNamespace).Create(vm)
				Expect(err).ToNot(HaveOccurred())
				DeferCleanup(func() {
					err := ApiClient.VirtualMachine(testNamespace).Delete(vm.Name, &metav1.DeleteOptions{})
					if err != nil && !errors.IsNotFound(err) {
						Expect(err).ToNot(HaveOccurred())
					}
					Eventually(func() bool {
						_, err := ApiClient.VirtualMachineInstance(vm.Namespace).Get(vm.Name, &metav1.GetOptions{})
						return errors.IsNotFound(err)
					}, time.Minute, time.Second).Should(BeTrue())
				})

				Eventually(func(g Gomega) {
					vmi, err := ApiClient.VirtualMachineInstance(vm.Namespace).Get(vm.Name, &metav1.GetOptions{})
					g.Expect(err).ToNot(HaveOccurred())
					g.Expect(vmi.Status.Phase).To(Equal(kubevirtcorev1.Running))
				}, time.Minute, time.Second).Should(Succeed())

				// Get the vnc token
				tokenUrl, err := url.JoinPath(httpUrlBase, testNamespace, vmiName, tokenEndpoint)
				Expect(err).ToNot(HaveOccurred())

				code, body, err := httpGet(tokenUrl, saToken, httpClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(code).To(Equal(http.StatusOK))

				tokenResponse := &api.TokenResponse{}
				Expect(json.Unmarshal(body, tokenResponse)).To(Succeed())
				Expect(tokenResponse.Token).ToNot(BeEmpty())

				vncToken = tokenResponse.Token
			})

			It("should fail if VMI does not exist", func() {
				// Delete the VM
				err := ApiClient.VirtualMachine(testNamespace).Delete(vm.Name, &metav1.DeleteOptions{})
				if err != nil && !errors.IsNotFound(err) {
					Expect(err).ToNot(HaveOccurred())
				}
				Eventually(func() bool {
					_, err := ApiClient.VirtualMachineInstance(testNamespace).Get(vm.Name, &metav1.GetOptions{})
					return errors.IsNotFound(err)
				}, time.Minute, time.Second).Should(BeTrue())

				// Try to access the VNC
				dialer.Subprotocols = []string{subprotocolPrefix + vncToken}

				conn, response, err := dialer.Dial(vncUrl, nil)
				if conn != nil {
					Expect(conn.Close()).To(Succeed())
					Fail("Websocket connection should not succeed.")
				}
				Expect(err).To(MatchError(websocket.ErrBadHandshake))

				Expect(response.StatusCode).To(Equal(http.StatusNotFound))
				Expect(io.ReadAll(response.Body)).To(ContainSubstring("VirtualMachineInstance does no exist"))
			})

			It("should proxy VNC connection", func() {
				dialer.Subprotocols = []string{subprotocolPrefix + vncToken, "base64.binary.k8s.io"}

				conn, _, err := dialer.Dial(vncUrl, nil)
				Expect(err).ToNot(HaveOccurred())

				done := make(chan struct{})
				streamer := kubecli.NewWebsocketStreamer(conn, done)
				defer close(done)

				vncClient, err := vnc.Client(streamer.AsConn(), &vnc.ClientConfig{})
				Expect(err).ToNot(HaveOccurred())
				Expect(vncClient.Close()).To(Succeed())
			})

			It("should fail if token is expired", func() {
				// Get the vnc token
				tokenUrl, err := url.JoinPath(httpUrlBase, testNamespace, vmiName, tokenEndpoint)
				Expect(err).ToNot(HaveOccurred())

				code, tokenBody, err := httpGet(tokenUrl+"?duration=1s", saToken, httpClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(code).To(Equal(http.StatusOK))

				tokenResponseObj := &api.TokenResponse{}
				Expect(json.Unmarshal(tokenBody, tokenResponseObj)).To(Succeed())
				Expect(tokenResponseObj.Token).ToNot(BeEmpty())

				vncTokenWithTimeout := tokenResponseObj.Token

				// Wait until the token expires
				time.Sleep(2 * time.Second)

				dialer.Subprotocols = []string{subprotocolPrefix + vncTokenWithTimeout}

				conn, response, err := dialer.Dial(vncUrl, nil)
				if conn != nil {
					_ = conn.Close()
					Fail("Websocket connection should not succeed.")
				}
				Expect(err).To(MatchError(websocket.ErrBadHandshake))

				Expect(response.StatusCode).To(Equal(http.StatusUnauthorized))
				Expect(io.ReadAll(response.Body)).To(ContainSubstring("request is not authenticated"))
			})
		})
	})
})

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

func testVm(name string) *kubevirtcorev1.VirtualMachine {
	const (
		containerDiskName = "containerdisk"
		cloudinitDiskName = "cloudinitdisk"

		image = "quay.io/kubevirt/cirros-container-disk-demo:20221123_4b34866cf"
	)

	return &kubevirtcorev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Spec: kubevirtcorev1.VirtualMachineSpec{
			Running: pointer.BoolPtr(true),
			Template: &kubevirtcorev1.VirtualMachineInstanceTemplateSpec{
				Spec: kubevirtcorev1.VirtualMachineInstanceSpec{
					Domain: kubevirtcorev1.DomainSpec{
						Devices: kubevirtcorev1.Devices{
							Disks: []kubevirtcorev1.Disk{{
								Name: containerDiskName,
								DiskDevice: kubevirtcorev1.DiskDevice{
									Disk: &kubevirtcorev1.DiskTarget{
										Bus: "virtio",
									},
								},
							}, {
								Name: cloudinitDiskName,
								DiskDevice: kubevirtcorev1.DiskDevice{
									Disk: &kubevirtcorev1.DiskTarget{
										Bus: "virtio",
									},
								},
							}},
						},
						Resources: kubevirtcorev1.ResourceRequirements{
							Requests: core.ResourceList{
								core.ResourceMemory: resource.MustParse("128Mi"),
							},
						},
					},
					Volumes: []kubevirtcorev1.Volume{{
						Name: containerDiskName,
						VolumeSource: kubevirtcorev1.VolumeSource{
							ContainerDisk: &kubevirtcorev1.ContainerDiskSource{
								Image: image,
							},
						},
					}, {
						Name: cloudinitDiskName,
						VolumeSource: kubevirtcorev1.VolumeSource{
							CloudInitNoCloud: &kubevirtcorev1.CloudInitNoCloudSource{
								UserData: "#!/bin/sh\n\necho 'printed from cloud-init userdata'\n",
							},
						},
					}},
				},
			},
		},
	}
}
