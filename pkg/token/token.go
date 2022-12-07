package token

import "github.com/golang-jwt/jwt/v4"

type Claims struct {
	jwt.RegisteredClaims

	Name      string `json:"nm,omitempty"`
	Namespace string `json:"nmspc,omitempty"`
	UID       string `json:"uid,omitempty"`
}

func (c *Claims) Valid() error {
	if err := c.RegisteredClaims.Valid(); err != nil {
		return err
	}

	if c.Name == "" || c.Namespace == "" || c.UID == "" {
		return &jwt.ValidationError{
			Inner:  jwt.ErrTokenInvalidClaims,
			Errors: jwt.ValidationErrorClaimsInvalid,
		}
	}

	return nil
}

func NewSignedToken(claims *Claims, key []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func ParseToken(tokenString string, key []byte) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, err
	}
	return token.Claims.(*Claims), nil
}
