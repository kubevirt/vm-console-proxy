package authConfig

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/util/cert"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	framework "k8s.io/client-go/tools/cache/testing"
)

var _ = Describe("Auth config", func() {
	var (
		userHeaders        []string
		groupHeaders       []string
		extraPrefixHeaders []string

		configMap *v1.ConfigMap

		fakeSource *framework.FakeControllerSource
		authReader Reader
	)

	BeforeEach(func() {
		userHeaders = []string{"user-header-1", "user-header-2"}
		groupHeaders = []string{"group-header-1", "group-header-2"}
		extraPrefixHeaders = []string{"extra-prefix-header-1", "extra-prefix-header-2"}

		fakeSource = framework.NewFakeControllerSource()

		userHeadersJson, err := json.Marshal(userHeaders)
		Expect(err).ToNot(HaveOccurred())

		groupHeadersJson, err := json.Marshal(groupHeaders)
		Expect(err).ToNot(HaveOccurred())

		extraPrefixHeadersJson, err := json.Marshal(extraPrefixHeaders)
		Expect(err).ToNot(HaveOccurred())

		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      configMapName,
				Namespace: configMapNamespace,
			},
			Data: map[string]string{
				usernameHeadersKey:    string(userHeadersJson),
				groupHeadersKey:       string(groupHeadersJson),
				extraPrefixHeadersKey: string(extraPrefixHeadersJson),
				clientCaKey:           testCa,
			},
		}

		fakeSource.Add(configMap)

		authReader, err = createReaderFromListerWatcher(fakeSource)
		Expect(err).ToNot(HaveOccurred())
	})

	It("should read user headers from ConfigMap", func() {
		userHeadersInConfig, err := authReader.GetUserHeaders()
		Expect(err).ToNot(HaveOccurred())

		Expect(userHeadersInConfig).To(ContainElements(userHeaders))
	})

	It("should return default user header", func() {
		userHeadersInConfig, err := authReader.GetUserHeaders()
		Expect(err).ToNot(HaveOccurred())

		Expect(userHeadersInConfig).To(ContainElement(DefaultUserHeader))
	})

	It("should fail if user headers are missing", func() {
		delete(configMap.Data, usernameHeadersKey)
		fakeSource.Modify(configMap)

		Eventually(func() error {
			_, err := authReader.GetUserHeaders()
			return err
		}, time.Second, 100*time.Millisecond).
			Should(MatchError(ContainSubstring(usernameHeadersKey + " not found in configmap")))
	})

	It("should read group headers from ConfigMap", func() {
		groupHeadersInConfig, err := authReader.GetGroupHeaders()
		Expect(err).ToNot(HaveOccurred())

		Expect(groupHeadersInConfig).To(ContainElements(groupHeaders))
	})

	It("should return default group header", func() {
		groupHeadersInConfig, err := authReader.GetGroupHeaders()
		Expect(err).ToNot(HaveOccurred())

		Expect(groupHeadersInConfig).To(ContainElements(DefaultGroupHeader))
	})

	It("should fail group headers are missing", func() {
		delete(configMap.Data, groupHeadersKey)
		fakeSource.Modify(configMap)

		Eventually(func() error {
			_, err := authReader.GetGroupHeaders()
			return err
		}, time.Second, 100*time.Millisecond).
			Should(MatchError(ContainSubstring(groupHeadersKey + " not found in configmap")))
	})

	It("should read extras headers from ConfigMap", func() {
		extraPrefixHeadersInConfig, err := authReader.GetExtraHeaderPrefixes()
		Expect(err).ToNot(HaveOccurred())

		Expect(extraPrefixHeadersInConfig).To(ContainElements(extraPrefixHeaders))
	})

	It("should return default extras header prefix", func() {
		extraPrefixHeadersInConfig, err := authReader.GetExtraHeaderPrefixes()
		Expect(err).ToNot(HaveOccurred())

		Expect(extraPrefixHeadersInConfig).To(ContainElements(DefaultExtraHeaderPrefix))
	})

	It("should fail if extras headers are missing", func() {
		delete(configMap.Data, extraPrefixHeadersKey)
		fakeSource.Modify(configMap)

		Eventually(func() error {
			_, err := authReader.GetExtraHeaderPrefixes()
			return err
		}, time.Second, 100*time.Millisecond).
			Should(MatchError(ContainSubstring(extraPrefixHeadersKey + " not found in configmap")))
	})

	It("should read CA from ConfigMap", func() {
		clientCa, err := authReader.GetClientCA()
		Expect(err).ToNot(HaveOccurred())

		testCerts, err := cert.ParseCertsPEM([]byte(testCa))
		if err != nil {
			panic(fmt.Sprintf("failed to parse testCa: %v", err))
		}

		testCertPool := x509.NewCertPool()
		for _, crt := range testCerts {
			testCertPool.AddCert(crt)
		}

		Expect(clientCa.Equal(testCertPool)).To(BeTrue())
	})

	It("should fail if CA is missing", func() {
		delete(configMap.Data, clientCaKey)
		fakeSource.Modify(configMap)

		Eventually(func() error {
			_, err := authReader.GetClientCA()
			return err
		}, time.Second, 100*time.Millisecond).
			Should(MatchError(ContainSubstring(clientCaKey + " not found in configmap")))
	})
})

func TestAuthConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Auth-config Suite")
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
