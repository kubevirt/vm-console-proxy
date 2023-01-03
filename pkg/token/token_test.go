package token

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/golang-jwt/jwt/v4"
)

var _ = Describe("Token tests", func() {
	const tokenSigningKey = "some-random-data"

	var claims *Claims

	BeforeEach(func() {
		claims = &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
			Name:      "test-name",
			Namespace: "test-namespace",
			UID:       "test-uid",
		}
	})

	It("should create and parse token", func() {
		token, err := NewSignedToken(claims, []byte(tokenSigningKey))
		Expect(err).ToNot(HaveOccurred())

		parsedClaims, err := ParseToken(token, []byte(tokenSigningKey))
		Expect(err).ToNot(HaveOccurred())

		Expect(parsedClaims).To(Equal(claims))
	})

	Context("signature", func() {
		It("should fail to parse if signature is not valid", func() {
			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			// Edit signature of the token
			lastChar := token[len(token)-1]
			if lastChar == 'A' {
				lastChar = 'B'
			} else {
				lastChar = 'A'
			}

			invalidToken := token[:len(token)-1] + string(lastChar)

			_, err = ParseToken(invalidToken, []byte(tokenSigningKey))
			Expect(err).To(HaveOccurred())
		})

		It("should fail to parse if key is different", func() {
			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			_, err = ParseToken(token, []byte("different-key"))
			Expect(err).To(HaveOccurred())
		})
	})

	Context("claims", func() {
		It("should fail to parse if claims don't contain name", func() {
			claims.Name = ""

			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			_, err = ParseToken(token, []byte(tokenSigningKey))
			Expect(err).To(HaveOccurred())
		})

		It("should fail to parse if claims don't contain namespace", func() {
			claims.Namespace = ""

			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			_, err = ParseToken(token, []byte(tokenSigningKey))
			Expect(err).To(HaveOccurred())
		})

		It("should fail to parse if claims don't contain UID", func() {
			claims.UID = ""

			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			_, err = ParseToken(token, []byte(tokenSigningKey))
			Expect(err).To(HaveOccurred())
		})

		It("should fail to parse, if token is expired", func() {
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-24 * time.Hour))

			token, err := NewSignedToken(claims, []byte(tokenSigningKey))
			Expect(err).ToNot(HaveOccurred())

			_, err = ParseToken(token, []byte(tokenSigningKey))
			Expect(err).To(HaveOccurred())
		})
	})
})
