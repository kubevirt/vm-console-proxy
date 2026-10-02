package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TokenResponse is the response object from /token endpoint.
//
// +k8s:openapi-gen=true
type TokenResponse struct {
	Token               string      `json:"token"`
	ExpirationTimestamp metav1.Time `json:"expirationTimestamp"`
}

// TlsProfile is the TLS configuration for the proxy.
type TlsProfile struct {
	Ciphers       []string           `json:"ciphers,omitempty"`
	MinTLSVersion TLSProtocolVersion `json:"minTLSVersion,omitempty"`
	Groups        []TLSGroup         `json:"groups,omitempty"`
}

// TLSProtocolVersion is a way to specify the protocol version used for TLS connections.
type TLSProtocolVersion string

const (
	// VersionTLS10 is version 1.0 of the TLS security protocol.
	VersionTLS10 TLSProtocolVersion = "VersionTLS10"
	// VersionTLS11 is version 1.1 of the TLS security protocol.
	VersionTLS11 TLSProtocolVersion = "VersionTLS11"
	// VersionTLS12 is version 1.2 of the TLS security protocol.
	VersionTLS12 TLSProtocolVersion = "VersionTLS12"
	// VersionTLS13 is version 1.3 of the TLS security protocol.
	VersionTLS13 TLSProtocolVersion = "VersionTLS13"
)

// TLSGroup specifies the key exchange group used for TLS connections.
type TLSGroup string

const (
	// TLSGroupX25519 represents X25519.
	TLSGroupX25519 TLSGroup = "X25519"
	// TLSGroupSecP256r1 represents P-256 (secp256r1).
	TLSGroupSecP256r1 TLSGroup = "secp256r1"
	// TLSGroupSecP384r1 represents P-384 (secp384r1).
	TLSGroupSecP384r1 TLSGroup = "secp384r1"
	// TLSGroupSecP521r1 represents P-521 (secp521r1).
	TLSGroupSecP521r1 TLSGroup = "secp521r1"
	// TLSGroupX25519MLKEM768 represents X25519MLKEM768.
	TLSGroupX25519MLKEM768 TLSGroup = "X25519MLKEM768"
	// TLSGroupSecP256r1MLKEM768 represents SecP256r1MLKEM768.
	TLSGroupSecP256r1MLKEM768 TLSGroup = "SecP256r1MLKEM768"
	// TLSGroupSecP384r1MLKEM1024 represents SecP384r1MLKEM1024.
	TLSGroupSecP384r1MLKEM1024 TLSGroup = "SecP384r1MLKEM1024"
)
