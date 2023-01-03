package token

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// This string is base64 encoded random 256 bytes.
// It is used for generating key to sign tokens.
const seedString = "lSA4no/z5hR8AT0gesBWR6NaKAqgY328NscaM8eKUqG8HNOV6YWflO1w3qnYTFa8xnO5ANVuVKvbj03Eg5LFcaEtDSVA+5pesYq4vbfDVPVDD60T3lhgIJ5v7w9Gj68m/rPVysJQSyr73raMJAcR9Spp0yJ5s2SzWQ6lBsDQanC+yxS1fAccyzwwgTboyC+AZ/OmCim7Go2wh+F6Q6vR7V2ABBweN4l3ZGPjfZuKgmdWS0IpJjgnoQJNvgpUFUuo58H0vpLTLaIzHlJ+l/SYj7u9dYcAR+UxrbVyxTaxCQ4iLmgd8LEka1D2ADSrOvxtwM5faEzg3L9YwMCjn9xwTA=="

// CreateHmacKey creates a key by signing the seedString
func CreateHmacKey(key crypto.PrivateKey) ([]byte, error) {
	seedData, err := base64.StdEncoding.DecodeString(seedString)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode seed string: %s", err))
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("cannot cast private key type %T to crypto.Signer", key)
	}

	hash := crypto.SHA256

	hasher := hash.New()
	n, err := hasher.Write(seedData)
	if err != nil {
		return nil, fmt.Errorf("error generating hash: %w", err)
	}
	if n != len(seedData) {
		return nil, fmt.Errorf("error generating hash: returned length %d is less than expected %d", n, len(seedData))
	}

	// Passing crypto.Hash(0), so that hasher.Sum() is treated as message.
	// This is important, because not all Signer implementations support hashed messages.
	signature, err := signer.Sign(rand.Reader, hasher.Sum(nil), crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed signing seed string: %w", err)
	}

	return signature, nil
}
