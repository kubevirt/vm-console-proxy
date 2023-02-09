package v1alpha1

import (
	ocpv1 "github.com/openshift/api/config/v1"
)

// TokenResponse is the response object from /token endpoint.
type TokenResponse struct {
	Token string `json:"token"`
}

// TlsSecurityProfile is the TLS configuration for the proxy.
type TlsSecurityProfile = ocpv1.TLSSecurityProfile
