package tests

import (
	"context"
	"crypto/tls"
	"time"

	"sigs.k8s.io/yaml"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	api "github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	ocpconfigv1 "github.com/openshift/api/config/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kubevirt/vm-console-proxy/pkg/console"
)

var _ = Describe("TLS config", func() {

	It("should read config from ConfigMap", func() {
		Eventually(func(g Gomega) {
			connState, err := getTlsConnectionState()
			Expect(err).ToNot(HaveOccurred())

			Expect(connState.CipherSuite).To(BeElementOf(
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			))
			Expect(connState.Version).To(BeNumerically(">=", tls.VersionTLS12))
		}, 1*time.Minute, time.Second).Should(Succeed())
	})

	Context("with changed ConfigMap", func() {
		AfterEach(func() {
			RevertToOriginalConfigMap()
		})

		It("should reload config at runtime", func() {
			tlsProfile := &api.TlsSecurityProfile{
				Type:   ocpconfigv1.TLSProfileModernType,
				Modern: &ocpconfigv1.ModernTLSProfile{},
			}

			tlsProfileYaml, err := yaml.Marshal(tlsProfile)
			Expect(err).ToNot(HaveOccurred())

			UpdateConfigMap(func(configMap *core.ConfigMap) {
				configMap.Data[console.TlsProfileFile] = string(tlsProfileYaml)
			})

			Eventually(func(g Gomega) {
				connState, err := getTlsConnectionState()
				Expect(err).ToNot(HaveOccurred())

				Expect(connState.CipherSuite).To(BeElementOf(
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				))
				Expect(connState.Version).To(BeNumerically(">=", tls.VersionTLS13))
			}, 1*time.Minute, time.Second).Should(Succeed())
		})

		It("should use default config if file does not exist", func() {
			err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Delete(context.TODO(), configMapName, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			Eventually(func(g Gomega) {
				connState, err := getTlsConnectionState()
				Expect(err).ToNot(HaveOccurred())
				Expect(connState.Version).To(BeNumerically(">=", tls.VersionTLS10))
			}, 1*time.Minute, time.Second).Should(Succeed())
		})

		It("should reload config if file recreated after deletion", func() {
			Eventually(func() error {
				foundConfig, err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
				if err != nil {
					return err
				}

				delete(foundConfig.Data, console.TlsProfileFile)

				_, err = ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Update(context.TODO(), foundConfig, metav1.UpdateOptions{})
				return err
			}, 1*time.Minute, time.Second).Should(Succeed())

			// Wait until default values take effect
			Eventually(func(g Gomega) {
				connState, err := getTlsConnectionState()
				Expect(err).ToNot(HaveOccurred())
				Expect(connState.Version).To(BeNumerically(">=", tls.VersionTLS10))
			}, 1*time.Minute, time.Second).Should(Succeed())

			// Recreate file
			tlsProfile := &api.TlsSecurityProfile{
				Type: ocpconfigv1.TLSProfileCustomType,
				Custom: &ocpconfigv1.CustomTLSProfile{
					TLSProfileSpec: ocpconfigv1.TLSProfileSpec{
						Ciphers: []string{
							"TLS_AES_128_GCM_SHA256",
							"TLS_AES_256_GCM_SHA384",
							"TLS_CHACHA20_POLY1305_SHA256",
						},
						MinTLSVersion: ocpconfigv1.VersionTLS13,
					},
				},
			}

			tlsProfileYaml, err := yaml.Marshal(tlsProfile)
			Expect(err).ToNot(HaveOccurred())

			Eventually(func() error {
				foundConfig, err := ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Get(context.TODO(), configMapName, metav1.GetOptions{})
				if err != nil {
					return err
				}

				if foundConfig.Data == nil {
					foundConfig.Data = make(map[string]string)
				}
				foundConfig.Data[console.TlsProfileFile] = string(tlsProfileYaml)

				_, err = ApiClient.CoreV1().ConfigMaps(DeploymentNamespace).Update(context.TODO(), foundConfig, metav1.UpdateOptions{})
				return err
			}, 1*time.Minute, time.Second).Should(Succeed())

			Eventually(func(g Gomega) {
				connState, err := getTlsConnectionState()
				Expect(err).ToNot(HaveOccurred())

				Expect(connState.CipherSuite).To(BeElementOf(
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				))
				Expect(connState.Version).To(BeNumerically(">=", tls.VersionTLS13))
			}, 1*time.Minute, time.Second).Should(Succeed())
		})
	})
})

func getTlsConnectionState() (tls.ConnectionState, error) {
	conn, err := GetApiConnection()
	if err != nil {
		return tls.ConnectionState{}, err
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()

	err = tlsConn.Handshake()
	if err != nil {
		return tls.ConnectionState{}, err
	}

	return tlsConn.ConnectionState(), nil
}
