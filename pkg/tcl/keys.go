package tcl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func NewClientPrivateKey() (jwk.Key, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate key: %w", err)
	}
	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create jwk from key: %w", err)
	}
	return jwkKey, nil
}

func ClientPublicKey(jwkKey jwk.Key) (jwk.Key, error) {
	publicKey, err := jwkKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	return publicKey, nil
}

// generates a new client key and writes it to the given path
func NewClientPrivateKeyFile(path string) (jwk.Key, error) {
	jwkKey, err := NewClientPrivateKey()
	if err != nil {
		return nil, err
	}

	jsonPrk, err := json.Marshal(jwkKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal jwk: %w", err)
	}
	os.WriteFile(path, jsonPrk, 0600)

	return jwkKey, nil
}

func ClientPrivateKeyFromFile(path string) (jwk.Key, error) {
	keySet, err := jwk.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read key file: %w", err)
	}
	key, ok := keySet.Key(0)
	if !ok {
		return nil, fmt.Errorf("no key found in key file: %s", path)
	}
	return key, nil
}
