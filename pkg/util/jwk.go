package util

import (
	"crypto"
	"encoding/base64"
	"encoding/json"

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
