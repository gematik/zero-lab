package oidf

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func NewJwkFromJson(data string) (*Jwk, error) {
	key, err := jwk.ParseKey([]byte(data))
	if err != nil {
		return nil, err
	}
	return &Jwk{Key: key}, nil
}

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

func (j *Jwk) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var m map[string]interface{}
	if err := unmarshal(&m); err != nil {
		return err
	}

	json, err := json.Marshal(m)
	if err != nil {
		return err
	}

	key, err := jwk.ParseKey(json)
	if err != nil {
		return err
	}
	j.Key = key
	return nil
}

func (j *Jwk) AsSet() *Jwks {
	keys := jwk.NewSet()
	keys.AddKey(j.Key)
	return &Jwks{Keys: keys}
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
