package bff

import (
	"crypto/rand"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func EncryptWithDirectKeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jwe.Encrypt(payload, jwe.WithKey(jwa.DIRECT, key))
	}
}

func DecryptWithDirectKeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jwe.Decrypt(payload, jwe.WithKey(jwa.DIRECT, key))
	}
}

func SignWithHS256KeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jws.Sign(payload, jws.WithKey(jwa.HS256, key))
	}
}

func VerifyWithHS256KeyFunc(key []byte) func([]byte) ([]byte, error) {
	return func(payload []byte) ([]byte, error) {
		return jws.Verify(payload, jws.WithKey(jwa.HS256, key))
	}
}

// Generate a random key of the given length in bits.
func GenerateRandomKey(bits int) []byte {
	key := make([]byte, bits/8)
	_, err := rand.Read(key)
	if err != nil {
		// if random does not work, we have a big problem
		panic(err)
	}

	return key
}
