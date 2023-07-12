package fake

import (
	"crypto/x509"

	"github.com/kubevirt/vm-console-proxy/pkg/console/authConfig"
)

type FakeReader struct {
	GetUserHeadersFunc         func() ([]string, error)
	GetGroupHeadersFunc        func() ([]string, error)
	GetExtraHeaderPrefixesFunc func() ([]string, error)
	GetClientCAFunc            func() (*x509.CertPool, error)
}

func NewFakeReader() *FakeReader {
	return &FakeReader{
		GetUserHeadersFunc: func() ([]string, error) {
			return []string{authConfig.DefaultUserHeader}, nil
		},
		GetGroupHeadersFunc: func() ([]string, error) {
			return []string{authConfig.DefaultGroupHeader}, nil
		},
		GetExtraHeaderPrefixesFunc: func() ([]string, error) {
			return []string{authConfig.DefaultExtraHeaderPrefix}, nil
		},
	}
}

var _ authConfig.Reader = &FakeReader{}

func (f *FakeReader) GetUserHeaders() ([]string, error) {
	if f.GetUserHeadersFunc == nil {
		panic("Unexpected call to GetUserHeaders")
	}
	return f.GetUserHeadersFunc()
}

func (f *FakeReader) GetGroupHeaders() ([]string, error) {
	if f.GetGroupHeadersFunc == nil {
		panic("Unexpected call to GetGroupHeaders")
	}
	return f.GetGroupHeadersFunc()
}

func (f *FakeReader) GetExtraHeaderPrefixes() ([]string, error) {
	if f.GetExtraHeaderPrefixesFunc == nil {
		panic("Unexpected call to GetExtraHeaderPrefixes")
	}
	return f.GetExtraHeaderPrefixesFunc()
}

func (f *FakeReader) GetClientCA() (*x509.CertPool, error) {
	if f.GetClientCAFunc == nil {
		panic("Unexpected call to GetClientCA")
	}
	return f.GetClientCAFunc()
}

func (f *FakeReader) Stop() {
	// Intentionally empty
}
