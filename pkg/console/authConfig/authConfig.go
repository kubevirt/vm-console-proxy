package authConfig

import (
	"crypto/x509"
	"fmt"
	"math/rand"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
)

const (
	DefaultUserHeader        = "X-Remote-User"
	DefaultGroupHeader       = "X-Remote-Group"
	DefaultExtraHeaderPrefix = "X-Remote-Extra-"
)

const (
	configMapNamespace = "kube-system"
	configMapName      = "extension-apiserver-authentication"

	usernameHeadersKey    = "requestheader-username-headers"
	groupHeadersKey       = "requestheader-group-headers"
	extraPrefixHeadersKey = "requestheader-extra-headers-prefix"
	clientCaKey           = "requestheader-client-ca-file"
)

type Reader interface {
	GetUserHeaders() ([]string, error)
	GetGroupHeaders() ([]string, error)
	GetExtraHeaderPrefixes() ([]string, error)
	GetClientCA() (*x509.CertPool, error)

	Stop()
}

func CreateReader(cli cache.Getter) (Reader, error) {
	lw := cache.NewListWatchFromClient(cli, "configmaps", configMapNamespace,
		fields.OneTermEqualSelector("metadata.name", configMapName))

	return createReaderFromListerWatcher(lw)
}

// createReaderFromListerWatcher is called in unit tests to pass a mocked ListerWatcher,
// because it is difficult to create a regular ListerWatcher from a mocked REST client.
func createReaderFromListerWatcher(lw cache.ListerWatcher) (Reader, error) {
	if _, err := lw.List(metav1.ListOptions{Limit: 1}); err != nil {
		return nil, fmt.Errorf("error probing the ConfigMap resource: %w", err)
	}

	// Resulting resync period will be between 12 and 24 hours, like the default for k8s
	resync := resyncPeriod(12 * time.Hour)
	informer := cache.NewSharedIndexInformer(lw, &v1.ConfigMap{}, resync, cache.Indexers{})

	stopInformer := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		informer.Run(stopInformer)
	}()

	// TODO: allow to interrupt WaitForCacheSync()
	if !cache.WaitForCacheSync(make(chan struct{}), informer.HasSynced) {
		close(stopInformer)
		<-done
		return nil, fmt.Errorf("timed out waiting for caches to sync")
	}

	return &reader{
		informer: informer,
		stop:     stopInformer,
		done:     done,
	}, nil
}

// resyncPeriod computes the time interval a shared informer waits before resyncing with the api server
func resyncPeriod(minResyncPeriod time.Duration) time.Duration {
	factor := rand.Float64() + 1
	return time.Duration(float64(minResyncPeriod.Nanoseconds()) * factor)
}

type reader struct {
	informer cache.SharedIndexInformer
	stop     chan struct{}
	done     chan struct{}

	lastRevision       string
	userHeaders        []string
	groupHeaders       []string
	extraPrefixHeaders []string
	clientCa           *x509.CertPool
}

var _ Reader = &reader{}

func (r *reader) GetUserHeaders() ([]string, error) {
	if err := r.refreshCache(); err != nil {
		return nil, err
	}
	return r.userHeaders, nil
}

func (r *reader) GetGroupHeaders() ([]string, error) {
	if err := r.refreshCache(); err != nil {
		return nil, err
	}
	return r.groupHeaders, nil
}

func (r *reader) GetExtraHeaderPrefixes() ([]string, error) {
	if err := r.refreshCache(); err != nil {
		return nil, err
	}
	return r.extraPrefixHeaders, nil
}

func (r *reader) GetClientCA() (*x509.CertPool, error) {
	if err := r.refreshCache(); err != nil {
		return nil, err
	}
	return r.clientCa, nil
}

func (r *reader) Stop() {
	close(r.stop)
	<-r.done
}

func (r *reader) getConfigMap() (*v1.ConfigMap, error) {
	configMap, exists, err := r.informer.GetStore().GetByKey(fmt.Sprintf("%s/%s", configMapNamespace, configMapName))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("configmap %s/%s not found", configMapNamespace, configMapName)
	}
	return configMap.(*v1.ConfigMap), nil
}

func (r *reader) refreshCache() error {
	configMap, err := r.getConfigMap()
	if err != nil {
		return err
	}

	if r.lastRevision == configMap.ResourceVersion {
		return nil
	}

	userHeaders, err := getStringsFromConfigMap(configMap, usernameHeadersKey)
	if err != nil {
		return err
	}
	userHeaders = append(userHeaders, DefaultUserHeader)

	groupHeaders, err := getStringsFromConfigMap(configMap, groupHeadersKey)
	if err != nil {
		return err
	}
	groupHeaders = append(groupHeaders, DefaultGroupHeader)

	extraPrefixHeaders, err := getStringsFromConfigMap(configMap, extraPrefixHeadersKey)
	if err != nil {
		return err
	}
	extraPrefixHeaders = append(extraPrefixHeaders, DefaultExtraHeaderPrefix)

	requestHeaderClientCA, ok := configMap.Data[clientCaKey]
	if !ok {
		return fmt.Errorf("requestheader-client-ca-file not found in configmap %s/%s", configMapNamespace, configMapName)
	}

	certs, err := cert.ParseCertsPEM([]byte(requestHeaderClientCA))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	for _, crt := range certs {
		pool.AddCert(crt)
	}

	r.userHeaders = userHeaders
	r.groupHeaders = groupHeaders
	r.extraPrefixHeaders = extraPrefixHeaders
	r.clientCa = pool
	r.lastRevision = configMap.ResourceVersion
	return nil
}

func getStringsFromConfigMap(configMap *v1.ConfigMap, key string) ([]string, error) {
	data, ok := configMap.Data[key]
	if !ok {
		return nil, fmt.Errorf("%s not found in configmap %s/%s", key, configMapNamespace, configMapName)
	}
	if len(data) == 0 {
		return nil, nil
	}

	var result []string
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return result, nil
}
