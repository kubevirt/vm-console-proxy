package tlsconfig

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	ocpconfigv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/util/cert"

	"github.com/kubevirt/vm-console-proxy/api/v1alpha1"
)

const (
	configDir      = "/config"
	tlsProfileFile = "tls-profile-v1alpha1.yaml"
)

func Create() (*tls.Config, error) {
	tlsProfile, err := loadTlsProfile()
	if err != nil {
		return nil, fmt.Errorf("could not load tls config: %w", err)
	}

	ciphers, minVersion, err := getTlsCiphersAndMinVersion(tlsProfile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		CipherSuites: ciphers,
		MinVersion:   minVersion,
	}, nil
}

func loadTlsProfile() (*v1alpha1.TlsSecurityProfile, error) {
	file, err := os.Open(filepath.Join(configDir, tlsProfileFile))
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	// It's ok to ignore error on close, because the file is opened of reading
	defer func() { _ = file.Close() }()

	result := &v1alpha1.TlsSecurityProfile{}
	err = yaml.NewYAMLToJSONDecoder(file).Decode(result)
	if err != nil {
		return nil, fmt.Errorf("error decoding tls config: %w", err)
	}
	return result, nil
}

func getTlsCiphersAndMinVersion(tlsProfile *v1alpha1.TlsSecurityProfile) ([]uint16, uint16, error) {
	var profile *ocpconfigv1.TLSProfileSpec
	if tlsProfile.Type == ocpconfigv1.TLSProfileCustomType {
		if tlsProfile.Custom == nil {
			return nil, 0, fmt.Errorf("tls profile \"custom\" field is nil")
		}
		profile = &tlsProfile.Custom.TLSProfileSpec
	} else {
		var exists bool
		profile, exists = ocpconfigv1.TLSProfiles[tlsProfile.Type]
		if !exists {
			return nil, 0, fmt.Errorf("unknown profile type: %s", tlsProfile.Type)
		}
	}

	ciphers := getCipherSuites(profile)
	minVersion, err := crypto.TLSVersion(string(profile.MinTLSVersion))
	if err != nil {
		return nil, 0, err
	}

	return ciphers, minVersion, nil
}

func getCipherSuites(profileSpec *ocpconfigv1.TLSProfileSpec) []uint16 {
	tlsCiphers := make(map[string]*tls.CipherSuite, len(tls.CipherSuites()))
	for _, suite := range tls.CipherSuites() {
		tlsCiphers[suite.Name] = suite
	}

	cipherIds := make([]uint16, 0, len(profileSpec.Ciphers))
	for _, ianaCipher := range crypto.OpenSSLToIANACipherSuites(profileSpec.Ciphers) {
		if cipher, found := tlsCiphers[ianaCipher]; found {
			cipherIds = append(cipherIds, cipher.ID)
		}
	}

	return cipherIds
}

func LoadCertificates(certPath, keyPath string) (*tls.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	crt, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %v\n", err)
	}
	leaf, err := cert.ParseCertsPEM(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load leaf certificate: %v\n", err)
	}
	crt.Leaf = leaf[0]
	return &crt, nil
}
