// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package oidf

import (
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/openid"
)

// NewJwkFromJSON parses a single JWK from its JSON form.
func NewJwkFromJSON(data string) (*Jwk, error) {
	key, err := openid.ParseKey([]byte(data))
	if err != nil {
		return nil, err
	}
	return &Jwk{Key: key}, nil
}

// Jwk holds one key, or none while Key is nil, in the form configuration reads and writes: a plain JWK.
type Jwk struct {
	Key *jose.JSONWebKey
}

// MarshalJSON writes the key as a JWK (RFC 7517).
func (j *Jwk) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.Key)
}

// UnmarshalJSON parses a JWK and replaces the wrapped key.
func (j *Jwk) UnmarshalJSON(data []byte) error {
	key, err := openid.ParseKey(data)
	if err != nil {
		return err
	}
	j.Key = key
	return nil
}

// UnmarshalYAML parses a JWK written as a YAML mapping and replaces the wrapped key.
func (j *Jwk) UnmarshalYAML(unmarshal func(any) error) error {
	var m map[string]any
	if err := unmarshal(&m); err != nil {
		return err
	}

	json, err := json.Marshal(m)
	if err != nil {
		return err
	}

	key, err := openid.ParseKey(json)
	if err != nil {
		return err
	}
	j.Key = key
	return nil
}

// AsSet returns a key set holding only this key. It fails if no key is set.
func (j *Jwk) AsSet() (*Jwks, error) {
	if j.Key == nil {
		return nil, errors.New("no key set")
	}
	return &Jwks{Keys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*j.Key}}}, nil
}

// Jwks holds a key set in the form entity statements carry it, a JWK Set in JSON.
type Jwks struct {
	Keys *jose.JSONWebKeySet
}

// MarshalJSON writes the keys as a JWK Set (RFC 7517 §5).
func (j *Jwks) MarshalJSON() ([]byte, error) {
	return json.Marshal(j.Keys)
}

// UnmarshalJSON parses a JWK Set and replaces the wrapped set. As [openid.ParseKeySet] leaves out entries it cannot
// use, marshalling a set read from elsewhere does not reproduce those.
func (j *Jwks) UnmarshalJSON(data []byte) error {
	keys, err := openid.ParseKeySet(data)
	if err != nil {
		return err
	}
	j.Keys = keys
	return nil
}
