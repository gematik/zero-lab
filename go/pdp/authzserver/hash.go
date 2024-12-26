package authzserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// HashSecret returns the hash of the given secret using PBKDF2
func HashSecret(secret string) (string, error) {
	saltLength := 16
	iterations := 100000
	keyLength := 32

	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	derivedKey := pbkdf2.Key([]byte(secret), salt, iterations, keyLength, sha256.New)
	saltB64 := base64.RawURLEncoding.EncodeToString(salt)
	keyB64 := base64.RawURLEncoding.EncodeToString(derivedKey)

	return saltB64 + "." + keyB64, nil
}

func VerifySecretHash(secret, hash string) (bool, error) {
	parts := strings.Split(hash, ".")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid hash format")
	}

	salt, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	derivedKey := pbkdf2.Key([]byte(secret), salt, 100000, 32, sha256.New)
	keyB64 := base64.RawURLEncoding.EncodeToString(derivedKey)

	return keyB64 == parts[1], nil
}
