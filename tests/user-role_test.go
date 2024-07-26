package tests

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"

	authzv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	proxy "github.com/kubevirt/vm-console-proxy/api/v1"
)

var _ = Describe("Role for token generation", func() {
	const (
		clusterRoleName = "token.kubevirt.io:generate"
	)

	It("should exist", func() {
		_, err := ApiClient.RbacV1().ClusterRoles().Get(context.TODO(), clusterRoleName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())
	})

	It("should be able to access token generation endpoint", func() {
		sa := &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "token-generator-user",
				Namespace:    testNamespace,
			},
		}

		sa, err := ApiClient.CoreV1().ServiceAccounts(testNamespace).Create(context.TODO(), sa, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := ApiClient.CoreV1().ServiceAccounts(testNamespace).Delete(context.TODO(), sa.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		roleBinding := &rbac.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      sa.Name + "-role-binding",
				Namespace: testNamespace,
			},
			Subjects: []rbac.Subject{{
				Kind:      "ServiceAccount",
				Name:      sa.Name,
				Namespace: testNamespace,
			}},
			RoleRef: rbac.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRoleName,
			},
		}

		roleBinding, err = ApiClient.RbacV1().RoleBindings(testNamespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := ApiClient.RbacV1().RoleBindings(testNamespace).Delete(context.TODO(), roleBinding.Name, metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		saUserName := fmt.Sprintf("system:serviceaccount:%s:%s", sa.GetNamespace(), sa.GetName())

		subjectAccessReview := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{
					Namespace:   testNamespace,
					Verb:        "get",
					Group:       proxy.Group,
					Version:     proxy.Version,
					Resource:    "virtualmachines",
					Subresource: "vnc",
				},
				User:   saUserName,
				Groups: []string{"system:serviceaccounts"},
			},
		}

		subjectAccessReview, err = ApiClient.AuthorizationV1().SubjectAccessReviews().Create(context.TODO(), subjectAccessReview, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		Expect(subjectAccessReview.Status.Allowed).To(BeTrue(),
			fmt.Sprintf("Access is not allowed: %s", subjectAccessReview.Status.Reason),
		)
	})
})
