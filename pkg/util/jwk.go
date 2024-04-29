package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// small trick to make jwk.Key JSON-serializable
type Jwk struct {
	Key jwk.Key
}

func (j *Jwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.Key)
}

func (j *Jwk) UnmarshalJSON(data []byte) error {
	key, err := jwk.ParseKey(data)
	if err != nil {
		return err
	}
	j.Key = key
	return nil
}

func (j *Jwk) ThumbprintString(hf crypto.Hash) (string, error) {
	t, err := j.Key.Thumbprint(hf)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

// small trick to make jwk.Set JSON-serializable
type Jwks struct {
	Keys jwk.Set
}

func (j *Jwks) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.Keys)
}

func (j *Jwks) UnmarshalJSON(data []byte) error {
	keys, err := jwk.Parse(data)
	if err != nil {
		return err
	}
	j.Keys = keys
	return nil
}

func RandomJWK() (jwk.Key, error) {
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
