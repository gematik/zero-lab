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

func (s SecretString) Value() string {
	return s.value
}

func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.value)
}

func (s *SecretString) UnmarshalJSON(data []byte) error {

	if err := json.Unmarshal(data, &s.value); err != nil {
		return fmt.Errorf("unable to unmarshal secret: %w", err)
	}

	return nil
}

func (s *SecretString) UnmarshalYAML(unmarshal func(any) error) error {
	if err := unmarshal(&s.value); err != nil {
		return fmt.Errorf("unable to unmashal secret: %w", err)
	}
	return nil
}

func (s SecretString) MarshalYAML() (any, error) {
	return s.value, nil
}
