package tlsconfig

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	"k8s.io/client-go/util/cert"
	"sigs.k8s.io/yaml"

	"github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	"github.com/kubevirt/vm-console-proxy/pkg/filewatch"
)

var _ = Describe("TlsConfig", func() {
	const (
		certHostName = "unittest.test"
	)

	var (
		configDir     string
		tlsConfigPath string

		certAndKeyDir string
		certPath      string
		keyPath       string

		configWatch Watch
	)

	BeforeEach(func() {
		tlsProfile := &v1alpha1.TlsSecurityProfile{
			Type:         ocpconfigv1.TLSProfileIntermediateType,
			Intermediate: &ocpconfigv1.IntermediateTLSProfile{},
		}
		tlsProfileYaml, err := yaml.Marshal(tlsProfile)
		Expect(err).ToNot(HaveOccurred())

		tmpDir := GinkgoT().TempDir()
		configDir := filepath.Join(tmpDir, "test-config")
		Expect(os.MkdirAll(configDir, 0755)).To(Succeed())

		const tlsConfigName = "tls-profile.yaml"
		tlsConfigPath = filepath.Join(configDir, tlsConfigName)
		Expect(os.WriteFile(tlsConfigPath, tlsProfileYaml, 0666)).To(Succeed())

		certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(certHostName, nil, nil)
		Expect(err).ToNot(HaveOccurred())

		certAndKeyDir := filepath.Join(tmpDir, "test-cert-and-key")
		Expect(os.MkdirAll(certAndKeyDir, 0755)).To(Succeed())

		const certName = "vm-console-proxy.crt"
		certPath = filepath.Join(certAndKeyDir, certName)
		Expect(os.WriteFile(certPath, certBytes, 0666)).To(Succeed())

		const keyName = "vm-console-proxy.key"
		keyPath = filepath.Join(certAndKeyDir, keyName)
		Expect(os.WriteFile(keyPath, keyBytes, 0666)).To(Succeed())

		configWatch = NewWatch(configDir, tlsConfigName, certAndKeyDir, certName, keyName)
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
		var (
			mockWatch *mockFileWatch
		)

		BeforeEach(func() {
			mockWatch = newMockFileWatch()
			Expect(configWatch.AddToFilewatch(mockWatch)).To(Succeed())

			configWatch.Reload()
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

			mockWatch.Trigger(configDir)

			config, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())

			Expect(config.CipherSuites).ToNot(Equal(originalConfig.CipherSuites))
			Expect(config.MinVersion).ToNot(Equal(originalConfig.MinVersion))

			Expect(config.CipherSuites).To(BeEmpty())
			Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		})

		It("should fail if config is invalid", func() {
			func() {
				configFile, err := os.Create(tlsConfigPath)
				Expect(err).ToNot(HaveOccurred())
				defer configFile.Close()
				_, err = configFile.WriteString("This is definitely not a valid YAML")
				Expect(err).ToNot(HaveOccurred())
			}()

			mockWatch.Trigger(configDir)

			_, err := configWatch.GetConfig()
			Expect(err).To(MatchError(ContainSubstring("error decoding tls config")))
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

			mockWatch.Trigger(certAndKeyDir)

			config, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config.Certificates).To(HaveLen(1))
			Expect(config.Certificates[0].Leaf.DNSNames).To(ConsistOf(newDnsName))
		})

		It("should fail if certificate is invalid", func() {
			func() {
				certFile, err := os.Create(certPath)
				Expect(err).ToNot(HaveOccurred())
				defer certFile.Close()

				_, err = certFile.WriteString("This is invalid certificate file")
				Expect(err).ToNot(HaveOccurred())
			}()

			mockWatch.Trigger(certAndKeyDir)

			_, err := configWatch.GetConfig()
			Expect(err).To(MatchError(ContainSubstring("failed to load certificate")))
		})

		It("should use default if file is deleted", func() {
			Expect(os.Remove(tlsConfigPath)).ToNot(HaveOccurred())

			mockWatch.Trigger(configDir)

			config, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config.CipherSuites).To(BeEmpty())
			Expect(config.MinVersion).To(BeZero())
		})
	})
})

type mockFileWatch struct {
	running   atomic.Bool
	callbacks map[string]func()
}

var _ filewatch.Watch = &mockFileWatch{}

func newMockFileWatch() *mockFileWatch {
	return &mockFileWatch{
		callbacks: make(map[string]func()),
	}
}

func (m *mockFileWatch) Add(path string, callback func()) error {
	m.callbacks[path] = callback
	return nil
}

func (m *mockFileWatch) Run(_ <-chan struct{}) error {
	panic("not implemented in mock")
}

func (m *mockFileWatch) IsRunning() bool {
	panic("not implemented in mock")
}

func (m *mockFileWatch) Trigger(path string) {
	for callbackPath, callback := range m.callbacks {
		if strings.HasPrefix(callbackPath, path) {
			callback()
		}
	}
}

func TestTlsConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TLS Config Suite")
}
