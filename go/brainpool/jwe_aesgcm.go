package brainpool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Encrypts a given plaintext using AES-GCM with an IV and AAD, returning the IV, tag, and ciphertext.
func encryptAESGCMWithIVAndAAD(key, plaintext, aad []byte) ([]byte, []byte, []byte, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a GCM block cipher mode instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a nonce (IV) for AES-GCM; it must be 12 bytes for optimal security
	iv := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, nil, err
	}

	// Encrypt the plaintext with the IV and AAD
	ciphertext := aesGCM.Seal(nil, iv, plaintext, aad)

	// Extract the tag from the end of the ciphertext
	tag := ciphertext[len(ciphertext)-aesGCM.Overhead():]
	ciphertext = ciphertext[:len(ciphertext)-aesGCM.Overhead()]

	return iv, tag, ciphertext, nil
}

// Decrypts the ciphertext using AES-GCM with a provided IV, tag, and AAD.
func decryptAESGCMWithIVAndAAD(key, iv, tag, ciphertext, aad []byte) (string, error) {
	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create a GCM block cipher mode instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Combine the ciphertext and tag for decryption
	ciphertextWithTag := append(ciphertext, tag...)

	// Decrypt the ciphertext with the provided IV and AAD
	plaintext, err := aesGCM.Open(nil, iv, ciphertextWithTag, aad)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
