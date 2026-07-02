package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// errRecordIntegrity is returned for any failure to authenticate a stored record: tampered ciphertext, a
// record copied onto a different kv key (AAD mismatch), or the wrong key. Callers treat it as "record absent
// + integrity alert" rather than a generic decode error.
var errRecordIntegrity = errors.New("session record failed integrity check (tampered, substituted, or wrong key)")

// recordCrypter seals and opens session records at rest. seal/open are closures that capture the key (or, in
// a future KMS-backed crypter, a KMS handle): the raw key material is touched ONLY inside the constructor and
// is never stored on the struct, returned, or referenced elsewhere — so a KMS crypter whose key never leaves
// the HSM can replace this one without changing any call site. The kv key (session id) is passed as GCM
// additional data, binding each ciphertext to its slot so a record cannot be substituted onto another key.
type recordCrypter struct {
	seal func(plaintext, aad []byte) ([]byte, error)
	open func(ciphertext, aad []byte) ([]byte, error)
}

// newAESRecordCrypter builds an AES-256-GCM crypter from a 32-byte key. The key is used here to construct the
// AEAD and is thereafter held only inside the closures (via the aead); it is not retained on the struct.
func newAESRecordCrypter(key []byte) (*recordCrypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("at-rest key must be 32 bytes (AES-256), got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &recordCrypter{
		seal: func(plaintext, aad []byte) ([]byte, error) {
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return nil, err
			}
			return aead.Seal(nonce, nonce, plaintext, aad), nil
		},
		open: func(ciphertext, aad []byte) ([]byte, error) {
			ns := aead.NonceSize()
			if len(ciphertext) < ns {
				return nil, errRecordIntegrity
			}
			plaintext, err := aead.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
			if err != nil {
				return nil, errRecordIntegrity
			}
			return plaintext, nil
		},
	}, nil
}
