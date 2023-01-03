package token

import (
	"crypto/ed25519"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Secret test", func() {
	It("should return the same value if the same private key is used", func() {
		_, privateKey, err := ed25519.GenerateKey(nil)
		Expect(err).ToNot(HaveOccurred())

		hmacKey1, err := CreateHmacKey(privateKey)
		Expect(err).ToNot(HaveOccurred())

		hmacKey2, err := CreateHmacKey(privateKey)
		Expect(err).ToNot(HaveOccurred())

		Expect(hmacKey1).To(Equal(hmacKey2))
	})

	It("should return different key depending on secret", func() {
		_, privateKey1, err := ed25519.GenerateKey(nil)
		Expect(err).ToNot(HaveOccurred())

		hmacKey1, err := CreateHmacKey(privateKey1)
		Expect(err).ToNot(HaveOccurred())

		_, privateKey2, err := ed25519.GenerateKey(nil)
		Expect(err).ToNot(HaveOccurred())

		hmacKey2, err := CreateHmacKey(privateKey2)
		Expect(err).ToNot(HaveOccurred())

		Expect(hmacKey1).ToNot(Equal(hmacKey2))
	})

	It("should fail if key is not crypto.Signer", func() {
		var invalidKeyType int
		_, err := CreateHmacKey(invalidKeyType)
		Expect(err).To(HaveOccurred())
	})
})
