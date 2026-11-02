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

package oidc

import (
	"encoding/json"
	"fmt"
)

// NewSecretString wraps value in a SecretString.
func NewSecretString(value string) SecretString {
	return SecretString{value}
}

// SecretString is a type that can be used to store secrets in a way that they are not printed in logs or marshaled to JSON.
type SecretString struct {
	value string
}

func (s SecretString) String() string {
	return "*****"
}

// Value returns the secret in clear.
func (s SecretString) Value() string {
	return s.value
}

// MarshalJSON writes the secret in clear; only String masks it.
func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.value)
}

// UnmarshalJSON reads the secret from a JSON string.
func (s *SecretString) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &s.value); err != nil {
		return fmt.Errorf("unable to unmarshal secret: %w", err)
	}

	return nil
}

// UnmarshalText reads the secret from a configuration file's string. There is no way back to text: a config
// written out again shows no secret.
func (s *SecretString) UnmarshalText(text []byte) error {
	s.value = string(text)
	return nil
}
