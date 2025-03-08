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

func (s SecretString) MarshalYAML() (interface{}, error) {
	return s.value, nil
}
