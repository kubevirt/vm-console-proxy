package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/client-go/util/cert"
	"sigs.k8s.io/yaml"

	"kubevirt.io/vm-console-proxy/api/v1"
	fakeAuth "kubevirt.io/vm-console-proxy/pkg/console/authConfig/fake"
	"kubevirt.io/vm-console-proxy/pkg/filewatch"
)

var _ = Describe("TlsConfig", func() {
	const (
		certHostName = "unittest.test"
	)

	var (
		testCiphersNames []string
		testCipherIds    []uint16

		configDir     string
		tlsConfigPath string

		certAndKeyDir string
		certPath      string
		keyPath       string

		fakeAuthConfig *fakeAuth.FakeReader
		testCertPool   *x509.CertPool

		configWatch Watch
	)

	BeforeEach(func() {
		testCiphersNames = []string{
			"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
			"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		}

		testCipherIds = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}

		tlsProfile := &v1.TlsProfile{
			Ciphers:       testCiphersNames,
			MinTLSVersion: v1.VersionTLS12,
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

		testCerts, err := cert.ParseCertsPEM([]byte(testCa))
		if err != nil {
			panic(fmt.Sprintf("failed to parse testCa: %v", err))
		}

		testCertPool = x509.NewCertPool()
		for _, crt := range testCerts {
			testCertPool.AddCert(crt)
		}

		fakeAuthConfig = &fakeAuth.FakeReader{
			GetClientCAFunc: func() (*x509.CertPool, error) {
				return testCertPool, nil
			},
		}

		configWatch = NewWatch(configDir, tlsConfigName, certAndKeyDir, certName, keyName, fakeAuthConfig)
	})

	It("should fail if config was not loaded", func() {
		_, err := configWatch.GetConfig()
		Expect(err).To(MatchError("tls profile not loaded"))
	})

	It("should load config from file", func() {
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.CipherSuites).To(ConsistOf(testCipherIds))
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("should use default ciphers, if ciphers are not specified", func() {
		tlsConfig := &v1.TlsProfile{
			MinTLSVersion: v1.VersionTLS12,
		}
		tlsConfigYaml, err := yaml.Marshal(tlsConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(tlsConfigPath, tlsConfigYaml, 0666)).To(Succeed())

		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		// Testing for nil specifically, because nil means default configuration.
		Expect(config.CipherSuites).To(BeNil())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("should use no ciphers if ciphers is an empty array", func() {
		tlsConfig := &v1.TlsProfile{
			Ciphers:       []string{},
			MinTLSVersion: v1.VersionTLS12,
		}
		tlsConfigYaml, err := yaml.Marshal(tlsConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(tlsConfigPath, tlsConfigYaml, 0666)).To(Succeed())

		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.CipherSuites).ToNot(BeNil())
		Expect(config.CipherSuites).To(BeEmpty())
		Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
	})

	It("should use default tls version, if MinTLSVersion is not specified", func() {
		tlsConfig := &v1.TlsProfile{
			Ciphers: testCiphersNames,
		}
		tlsConfigYaml, err := yaml.Marshal(tlsConfig)
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(tlsConfigPath, tlsConfigYaml, 0666)).To(Succeed())

		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.CipherSuites).To(ConsistOf(testCipherIds))
		Expect(config.MinVersion).To(BeZero())
	})

	It("should use default config if file does not exist", func() {
		Expect(os.Remove(tlsConfigPath)).ToNot(HaveOccurred())
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		// Testing for nil specifically, because nil means default configuration.
		Expect(config.CipherSuites).To(BeNil())
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

			tlsProfile := &v1.TlsProfile{
				Ciphers: []string{
					"TLS_AES_128_GCM_SHA256",
					"TLS_AES_256_GCM_SHA384",
					"TLS_CHACHA20_POLY1305_SHA256",
				},
				MinTLSVersion: v1.VersionTLS13,
			}
			tlsProfileYaml, err := yaml.Marshal(tlsProfile)
			Expect(err).ToNot(HaveOccurred())
			Expect(os.WriteFile(tlsConfigPath, tlsProfileYaml, 0666)).To(Succeed())

			mockWatch.Trigger(configDir)

			config, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())

			Expect(config.CipherSuites).ToNot(Equal(originalConfig.CipherSuites))
			Expect(config.MinVersion).ToNot(Equal(originalConfig.MinVersion))

			Expect(config.CipherSuites).To(ConsistOf(
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			))
			Expect(config.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
		})

		It("should fail if config is invalid", func() {
			Expect(os.WriteFile(tlsConfigPath, []byte("This is definitely not a valid YAML"), 0666)).To(Succeed())

			mockWatch.Trigger(configDir)

			_, err := configWatch.GetConfig()
			Expect(err).To(MatchError(ContainSubstring("error decoding tls config")))
		})

		It("should reload certificate on change", func() {
			const newDnsName = "new-name.test"
			certBytes, keyBytes, err := cert.GenerateSelfSignedCertKey(newDnsName, nil, nil)
			Expect(err).ToNot(HaveOccurred())

			Expect(os.WriteFile(certPath, certBytes, 0666)).To(Succeed())
			Expect(os.WriteFile(keyPath, keyBytes, 0666)).To(Succeed())

			mockWatch.Trigger(certAndKeyDir)

			config, err := configWatch.GetConfig()
			Expect(err).ToNot(HaveOccurred())
			Expect(config.Certificates).To(HaveLen(1))
			Expect(config.Certificates[0].Leaf.DNSNames).To(ConsistOf(newDnsName))
		})

		It("should fail if certificate is invalid", func() {
			Expect(os.WriteFile(certPath, []byte("This is invalid certificate file"), 0666)).To(Succeed())

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

	It("should read client CA from auth config", func() {
		configWatch.Reload()

		config, err := configWatch.GetConfig()
		Expect(err).ToNot(HaveOccurred())

		Expect(config.ClientCAs.Equal(testCertPool)).To(BeTrue())
	})

	It("if should fail if client CA is not in auth config", func() {
		fakeAuthConfig.GetClientCAFunc = func() (*x509.CertPool, error) {
			return nil, fmt.Errorf("error getting client CA")
		}

		configWatch.Reload()

		_, err := configWatch.GetConfig()
		Expect(err).To(MatchError("error getting client CA"))
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

// testCa is s self-signed certificate with that expires at 2033-07-23
const testCa = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfMCFEZRPwRupWsOa/rvrr85Ekqn376xMA0GCSqGSIb3DQEBCwUAMEIx
CzAJBgNVBAYTAlhYMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0Rl
ZmF1bHQgQ29tcGFueSBMdGQwHhcNMjMwNzI2MTM1NDU0WhcNMzMwNzIzMTM1NDU0
WjBCMQswCQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQK
DBNEZWZhdWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAqQPy+9HOhIubR9VJis16B4x+U42dNzdHLBzUrzT0Cdjv13DwHDES0SMq
Bh/PfEfIEc7brXYUijrQM5VWQxMaDxMhm98UKo+XUaQ3r9k/jEQEXsNCj+hL3soU
fAdPM+u1uHkpGYaYJGh2N0viD2nyXOuSAquTQAAQ+Vqqz5Y7eU1qILRgZvhtpBa6
QMkYF0JOVRwhBRLSft/e05vqP6bc0th/2mGFnheXxvtPpP6sH1NuJSxi0/8kHPYF
PvfWdXe3MG/0bF/6Tw3IntjBlOe5D/Ks5sD8lsB/yNLMDKOqjWLje/9IX1uhb8zc
N8uTYrooFzp4z0U7Ir+xOZelOUC1KwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCG
d5/Xzb/NAVZHEos+6oX0Hi3f4D1jHmcah3yEId/KsrS7SKm8boFyR7FlXZzLqSLt
IB8tTXrzehafHNuLJHOWFM4X1J48M/68lvEc2xM5KrWtg2G3CppA+b2q17AaYiuB
OhJYPlr1w6N7/hO8/CQdzRfSPj84252MDehH03pAyxme5sH7iwI/yL623lqJrA96
HyGQSDOtbnHhtz1REz+FziJnMR6AGoeHE7d/sZZt8WKi1Cc2FN/fZvQNx7RxvVSZ
6hvTouSE74Op+DmgDst7a3P8rED5ZV3+Q0E9GRYJypiL3rz9z4mDy+U+L0ZROZad
50PIG1NMnPahDQa/IdGC
-----END CERTIFICATE-----
`
