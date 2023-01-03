package v1alpha1

// TokenResponse is the response object from /token endpoint.
type TokenResponse struct {
	Token string `json:"token"`
}
