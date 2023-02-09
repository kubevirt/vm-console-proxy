package tlsconfig

import (
	"crypto/tls"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	"k8s.io/client-go/util/cert"
	"sigs.k8s.io/yaml"

	"github.com/kubevirt/vm-console-proxy/api/v1alpha1"
)

var _ = Describe("TlsConfig", func() {
	const (
		certHostName = "unittest.test"
	)

	var (
		tlsConfigPath string
		certPath      string
		keyPath       string

		configWatch Watch
	)

	createTempFile := func(pattern string, content []byte) string {
		tempFile, err := os.CreateTemp("", pattern)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() {
			err := os.Remove(tempFile.Name())
			if !errors.Is(err, os.ErrNotExist) {
				Expect(err).ToNot(HaveOccurred())
			}
		})
		defer tempFile.Close()

		_, err = tempFile.Write(content)
		Expect(err).ToNot(HaveOccurred())

		return tempFile.Name()
	}

	BeforeEach(func() {
		tlsProfile := &v1alpha1.TlsSecurityProfile{
			Type:         ocpconfigv1.TLSProfileIntermediateType,
			Intermediate: &ocpconfigv1.IntermediateTLSProfile{},
		}
		tlsProfileYaml, err := yaml.Marshal(tlsProfile)
		Expect(err).ToNot(HaveOccurred())

		certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(certHostName, nil, nil)
		Expect(err).ToNot(HaveOccurred())

		tlsConfigPath = createTempFile("vm-console-proxy-tls-config-*.yaml", tlsProfileYaml)
		certPath = createTempFile("vm-console-proxy-cert-*.crt", certBytes)
		keyPath = createTempFile("vm-console-proxy-key-*.key", keyBytes)

		configWatch = NewWatch(tlsConfigPath, certPath, keyPath)
	})

	It("should fail if config was not loaded", func() {
		_, err := configWatch.GetConfig()
		Expect(err).To(MatchError("tls profile not loaded"))
	})

	It("should load config from file", func() {
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.CipherSuites).To(ConsistOf(
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		))
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("should use default config if file does not exist", func() {
		Expect(os.Remove(tlsConfigPath)).ToNot(HaveOccurred())
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.CipherSuites).To(BeEmpty())
		Expect(config.MinVersion).To(BeZero())
	})

	It("should load certificate from file", func() {
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.Certificates).To(HaveLen(1))
		Expect(config.Certificates[0].Leaf.DNSNames).To(ConsistOf(certHostName))
	})

	Context("watching", func() {
		BeforeEach(func() {
			configWatch.Reload()

			done := make(chan struct{})
			DeferCleanup(func() {
				close(done)
			})

			go func() {
				defer GinkgoRecover()
				Expect(configWatch.Run(done)).To(Succeed())
			}()

			// Wait for a short time to let the watch goroutine run
			runtime.Gosched()
			Eventually(configWatch.IsRunning, time.Second, 50*time.Millisecond).Should(BeTrue())
		})

		It("should reload config on change", func() {
			originalConfig, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())

			func() {
				configFile, err := os.Create(tlsConfigPath)
				Expect(err).ToNot(HaveOccurred())
				defer configFile.Close()

				tlsProfile := &v1alpha1.TlsSecurityProfile{
					Type:   ocpconfigv1.TLSProfileModernType,
					Modern: &ocpconfigv1.ModernTLSProfile{},
				}
				tlsProfileYaml, err := yaml.Marshal(tlsProfile)
				Expect(err).ToNot(HaveOccurred())

				_, err = configFile.Write(tlsProfileYaml)
				Expect(err).ToNot(HaveOccurred())
			}()

			Eventually(func(g Gomega) {
				config, err := configWatch.GetConfig()
				g.Expect(err).ToNot(HaveOccurred())

				g.Expect(config.CipherSuites).ToNot(Equal(originalConfig.CipherSuites))
				g.Expect(config.MinVersion).ToNot(Equal(originalConfig.MinVersion))

				g.Expect(config.CipherSuites).To(BeEmpty())
				g.Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			}, 1*time.Second, 100*time.Millisecond).Should(Succeed())
		})

		It("should fail if config is invalid", func() {
			func() {
				configFile, err := os.Create(tlsConfigPath)
				Expect(err).ToNot(HaveOccurred())
				defer configFile.Close()
				_, err = configFile.WriteString("This is definitely not a valid YAML")
				Expect(err).ToNot(HaveOccurred())
			}()

			Eventually(func() error {
				_, err := configWatch.GetConfig()
				return err
			}, 1*time.Second, 100*time.Millisecond).Should(MatchError(ContainSubstring("error decoding tls config")))
		})

		It("should reload certificate on change", func() {
			const newDnsName = "new-name.test"
			certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(newDnsName, nil, nil)
			Expect(err).ToNot(HaveOccurred())

			func() {
				certFile, err := os.Create(certPath)
				Expect(err).ToNot(HaveOccurred())
				defer certFile.Close()

				_, err = certFile.Write(certBytes)
				Expect(err).ToNot(HaveOccurred())

				keyFile, err := os.Create(keyPath)
				Expect(err).ToNot(HaveOccurred())
				defer keyFile.Close()

				_, err = keyFile.Write(keyBytes)
				Expect(err).ToNot(HaveOccurred())
			}()

			Eventually(func(g Gomega) {
				config, err := configWatch.GetConfig()
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(config.Certificates).To(HaveLen(1))
				g.Expect(config.Certificates[0].Leaf.DNSNames).To(ConsistOf(newDnsName))
			}, 1*time.Second, 100*time.Millisecond).Should(Succeed())
		})

		It("should fail if certificate is invalid", func() {
			func() {
				certFile, err := os.Create(certPath)
				Expect(err).ToNot(HaveOccurred())
				defer certFile.Close()

				_, err = certFile.WriteString("This is invalid certificate file")
				Expect(err).ToNot(HaveOccurred())
			}()

			Eventually(func() error {
				_, err := configWatch.GetConfig()
				return err
			}, 1*time.Second, 100*time.Millisecond).Should(MatchError(ContainSubstring("failed to load certificate")))
		})

		It("should use default if file is deleted", func() {
			Expect(os.Remove(tlsConfigPath)).ToNot(HaveOccurred())

			Eventually(func(g Gomega) {
				config, err := configWatch.GetConfig()
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(config.CipherSuites).To(BeEmpty())
				g.Expect(config.MinVersion).To(BeZero())
			}, 1*time.Second, 100*time.Millisecond).Should(Succeed())
		})
	})
})

func TestTlsConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Config Suite")
}
