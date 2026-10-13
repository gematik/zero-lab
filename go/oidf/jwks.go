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

	"github.com/lestrrat-go/jwx/v3/jwk"
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

func (j *Jwk) UnmarshalYAML(unmarshal func(any) error) error {
	var m map[string]any
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
