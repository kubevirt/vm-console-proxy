package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"

	"github.com/golang-jwt/jwt/v4"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	kubevirtcorev1 "kubevirt.io/api/core/v1"

	api "github.com/kubevirt/vm-console-proxy/api/v1alpha1"
)

var _ = Describe("Kubevirt proxy", func() {
	var (
		saToken string
	)

	BeforeEach(func() {
		tokenRequest := &authnv1.TokenRequest{}
		tokenRequest, err := ApiClient.CoreV1().ServiceAccounts(testNamespace).CreateToken(context.TODO(), serviceAccountName, tokenRequest, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		saToken = tokenRequest.Status.Token
	})

	Context("/token endpoint", func() {

		It("should fail if not authenticated", func() {
			tokenUrl := getTokenUrl("test-vm")
			code, body, err := httpGet(tokenUrl, "", TestHttpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusForbidden))

			status := &metav1.Status{}
			Expect(json.Unmarshal(body, status)).To(Succeed())

			Expect(status.Reason).To(Equal(metav1.StatusReasonForbidden))
			Expect(status.Details).ToNot(BeNil())
			Expect(status.Details.Group).To(Equal("token.kubevirt.io"))
			Expect(status.Details.Kind).To(Equal("virtualmachines"))
		})

		It("should fail if not authorized to access vmi/vnc endpoint", func() {
			role, err := ApiClient.RbacV1().Roles(testNamespace).Get(context.TODO(), roleName, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			newRole := role.DeepCopy()
			// Removed the rule to allow accessing virtualmachineinstances/vnc
			newRole.Rules = []rbac.PolicyRule{{
				APIGroups: []string{"token.kubevirt.io"},
				Resources: []string{"virtualmachines/vnc"},
				Verbs:     []string{"get"},
			}}

			newRole, err = ApiClient.RbacV1().Roles(testNamespace).Update(context.TODO(), newRole, metav1.UpdateOptions{})
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				newRole.Rules = role.Rules
				newRole, err = ApiClient.RbacV1().Roles(testNamespace).Update(context.TODO(), newRole, metav1.UpdateOptions{})
				Expect(err).ToNot(HaveOccurred())
			})

			tokenUrl := getTokenUrl("test-vm")
			code, body, err := httpGet(tokenUrl, saToken, TestHttpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusUnauthorized))
			Expect(string(body)).To(BeEmpty())
		})

		It("should fail if VM does not exist", func() {
			tokenUrl := getTokenUrl("test-vm")
			code, body, err := httpGet(tokenUrl, saToken, TestHttpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusNotFound))
			Expect(string(body)).To(ContainSubstring("VirtualMachine does not exist"))
		})

		Context("with VM", func() {
			var (
				vmName string
			)

			BeforeEach(func() {
				vm := testVm("test-vm-")
				vm, err := ApiClient.VirtualMachine(testNamespace).Create(context.Background(), vm)
				Expect(err).ToNot(HaveOccurred())

				DeferCleanup(func() {
					err := ApiClient.VirtualMachine(testNamespace).Delete(context.Background(), vm.Name, &metav1.DeleteOptions{})
					if err != nil && !errors.IsNotFound(err) {
						Expect(err).ToNot(HaveOccurred())
					}
				})

				Eventually(func() error {
					_, err := ApiClient.VirtualMachineInstance(vm.Namespace).Get(context.Background(), vm.Name, &metav1.GetOptions{})
					return err
				}, 10*time.Minute, time.Second).Should(Succeed())

				vmName = vm.Name
			})

			It("should get token with default duration", func() {
				tokenUrl := getTokenUrl(vmName)
				code, body, err := httpGet(tokenUrl, saToken, TestHttpClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(code).To(Equal(http.StatusOK))

				tokenResponse := &api.TokenResponse{}
				Expect(json.Unmarshal(body, tokenResponse)).To(Succeed())
				Expect(tokenResponse.Token).ToNot(BeEmpty())
			})

			It("should get token with specified duration", func() {
				tokenUrl := getTokenUrl(vmName)

				code, body, err := httpGet(tokenUrl+"?duration=24h", saToken, TestHttpClient)
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

	Context("accessing kubevirt VMI/vnc endpoint", func() {
		It("should be able to access VMI/vnc endpoint using token", func() {
			vm := testVm("test-vm-")
			vm.Spec.Running = pointer.Bool(false)
			vm, err := ApiClient.VirtualMachine(testNamespace).Create(context.Background(), vm)
			Expect(err).ToNot(HaveOccurred())

			DeferCleanup(func() {
				err := ApiClient.VirtualMachine(testNamespace).Delete(context.Background(), vm.Name, &metav1.DeleteOptions{})
				if err != nil && !errors.IsNotFound(err) {
					Expect(err).ToNot(HaveOccurred())
				}
			})

			tokenUrl := getTokenUrl(vm.Name)
			code, body, err := httpGet(tokenUrl, saToken, TestHttpClient)
			Expect(err).ToNot(HaveOccurred())
			Expect(code).To(Equal(http.StatusOK))

			tokenResponse := &api.TokenResponse{}
			Expect(json.Unmarshal(body, tokenResponse)).To(Succeed())
			Expect(tokenResponse.Token).ToNot(BeEmpty())

			tokenReview := &authnv1.TokenReview{
				Spec: authnv1.TokenReviewSpec{
					Token: tokenResponse.Token,
				},
			}

			tokenReview, err = ApiClient.AuthenticationV1().TokenReviews().Create(context.TODO(), tokenReview, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(tokenReview.Status.Error).To(BeEmpty())
			Expect(tokenReview.Status.Authenticated).To(BeTrue())

			extras := map[string]authzv1.ExtraValue{}
			for key, value := range tokenReview.Status.User.Extra {
				extras[key] = authzv1.ExtraValue(value)
			}

			accessReview := &authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authzv1.ResourceAttributes{
						Namespace:   testNamespace,
						Name:        vm.Name,
						Verb:        "get",
						Group:       kubevirtcorev1.SubresourceGroupName,
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

			accessReview, err = ApiClient.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), accessReview, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			Expect(accessReview.Status.Allowed).To(BeTrue())
		})
	})
})

func getTokenUrl(vmName string) string {
	return GetApiUrlBase() + path.Join("namespaces", testNamespace, "virtualmachines", vmName, "vnc")
}

func testVm(namePrefix string) *kubevirtcorev1.VirtualMachine {
	const (
		containerDiskName = "containerdisk"
		cloudinitDiskName = "cloudinitdisk"

		image = "quay.io/kubevirt/cirros-container-disk-demo:20221123_4b34866cf"
	)

	return &kubevirtcorev1.VirtualMachine{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: namePrefix,
			Namespace:    testNamespace,
		},
		Spec: kubevirtcorev1.VirtualMachineSpec{
			Running: ptr.To(true),
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
