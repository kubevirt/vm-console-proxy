package tlsconfig

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/util/cert"
	"kubevirt.io/client-go/log"

	"github.com/kubevirt/vm-console-proxy/api/v1alpha1"
	"github.com/kubevirt/vm-console-proxy/pkg/console/authConfig"
	"github.com/kubevirt/vm-console-proxy/pkg/filewatch"
)

type Watch interface {
	AddToFilewatch(watch filewatch.Watch) error
	Reload()
	GetConfig() (*tls.Config, error)
}

func NewWatch(configDir, tlsProfileFileName, certAndKeyDir, certsName, keyName string, authConfig authConfig.Reader) Watch {
	return &watch{
		configDir:          configDir,
		tlsProfileFileName: tlsProfileFileName,
		tlsProfileError:    fmt.Errorf("tls profile not loaded"),

		certAndKeyDir: certAndKeyDir,
		certsName:     certsName,
		keyName:       keyName,
		certError:     fmt.Errorf("certificate not loaded"),

		authConfig: authConfig,
	}
}

type watch struct {
	lock sync.RWMutex

	configDir          string
	tlsProfileFileName string

	certAndKeyDir string
	certsName     string
	keyName       string

	tlsProfileError error
	ciphers         []uint16
	minTlsVersion   uint16

	certificate *tls.Certificate
	certError   error

	authConfig authConfig.Reader
}

func (w *watch) AddToFilewatch(watch filewatch.Watch) error {
	if err := watch.Add(w.configDir, w.reloadTlsProfile); err != nil {
		return err
	}
	return watch.Add(w.certAndKeyDir, w.reloadCertificate)
}

func (w *watch) Reload() {
	w.reloadTlsProfile()
	w.reloadCertificate()
}

func (w *watch) GetConfig() (*tls.Config, error) {
	clientCa, err := w.authConfig.GetClientCA()
	if err != nil {
		return nil, err
	}

	w.lock.RLock()
	defer w.lock.RUnlock()

	if w.tlsProfileError != nil {
		return nil, w.tlsProfileError
	}
	if w.certError != nil {
		return nil, w.certError
	}

	return &tls.Config{
		CipherSuites: w.ciphers,
		MinVersion:   w.minTlsVersion,
		Certificates: []tls.Certificate{*w.certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCa,
	}, nil
}

func (w *watch) reloadTlsProfile() {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.tlsProfileError = nil

	ciphers, minVersion, err := loadCipherSuitesAndMinVersion(filepath.Join(w.configDir, w.tlsProfileFileName))
	if errors.Is(err, os.ErrNotExist) {
		// Config file does not exist, using zero values for default
		w.ciphers = nil
		w.minTlsVersion = 0
		return
	}
	if err != nil {
		log.Log.Errorf("Failed to load TLS configuration: %s", err)
		w.tlsProfileError = fmt.Errorf("failed to load TLS configuration: %w", err)
		return
	}

	log.Log.Infof("Loaded TLS configuration.")
	{
		// TODO: only compute human readable strings on debug level.
		// For now, there is no easy way to test for logging level.
		if minVersion == 0 {
			log.Log.V(1).Infof("Min TLS version was not set in the config file. Using default.")
		} else {
			log.Log.V(1).Infof("Set min TLS version: %s", tls.VersionName(minVersion))
		}

		if ciphers == nil {
			log.Log.V(1).Infof("Ciphers were not set in the config file. Using default.")
		} else {
			cipherNames := make([]string, 0, len(ciphers))
			for _, cipher := range ciphers {
				cipherNames = append(cipherNames, tls.CipherSuiteName(cipher))
			}
			log.Log.V(1).Infof("Set ciphers: %s", strings.Join(cipherNames, ", "))
		}
	}

	w.ciphers = ciphers
	w.minTlsVersion = minVersion
}

func (w *watch) reloadCertificate() {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.certError = nil

	certificate, err := LoadCertificates(
		filepath.Join(w.certAndKeyDir, w.certsName),
		filepath.Join(w.certAndKeyDir, w.keyName),
	)
	if err != nil {
		w.certError = err
		return
	}

	log.Log.Infof("Loaded TLS certificate.")
	w.certificate = certificate
}

func loadCipherSuitesAndMinVersion(configPath string) ([]uint16, uint16, error) {
	tlsProfile, err := loadTlsProfile(configPath)
	if err != nil {
		return nil, 0, fmt.Errorf("could not load tls config: %w", err)
	}

	ciphers, err := getCipherSuites(tlsProfile.Ciphers)
	if err != nil {
		return nil, 0, fmt.Errorf("could not get cipher suite numbers: %w", err)
	}

	minVersion, err := getMinTlsVersion(tlsProfile.MinTLSVersion)
	if err != nil {
		return nil, 0, fmt.Errorf("could not get minimum TLS version: %w", err)
	}

	return ciphers, minVersion, nil
}

func loadTlsProfile(profilePath string) (*v1alpha1.TlsProfile, error) {
	file, err := os.Open(profilePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	// It's ok to ignore error on close, because the file is opened of reading
	defer func() { _ = file.Close() }()

	result := &v1alpha1.TlsProfile{}
	err = yaml.NewYAMLToJSONDecoder(file).Decode(result)
	if err != nil {
		return nil, fmt.Errorf("error decoding tls config: %w", err)
	}
	return result, nil
}

func getCipherSuites(cipherNames []string) ([]uint16, error) {
	if len(cipherNames) == 0 {
		// nil value has means default cipher suites will be used
		return nil, nil
	}

	result := make([]uint16, 0, len(cipherNames))

outerLoop:
	for _, cipherName := range cipherNames {
		for _, cipherSuite := range tls.CipherSuites() {
			if cipherName == cipherSuite.Name {
				result = append(result, cipherSuite.ID)
				continue outerLoop
			}
		}
		return nil, fmt.Errorf("unknown cipher suite: %v", cipherName)
	}

	return result, nil
}

func getMinTlsVersion(version v1alpha1.TLSProtocolVersion) (uint16, error) {
	switch version {
	case "":
		return 0, nil
	case v1alpha1.VersionTLS10:
		return tls.VersionTLS10, nil
	case v1alpha1.VersionTLS11:
		return tls.VersionTLS11, nil
	case v1alpha1.VersionTLS12:
		return tls.VersionTLS12, nil
	case v1alpha1.VersionTLS13:
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
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
