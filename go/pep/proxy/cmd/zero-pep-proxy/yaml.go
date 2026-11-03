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

package main

import (
	"bytes"
	"fmt"
	"os"

	yaml "go.yaml.in/yaml/v4"

	"github.com/gematik/zero-lab/go/openid/providers"
)

// loadYAML reads a configuration file, expanding ${VAR} placeholders from the environment. An unknown key is an
// error, so an outdated file stops the start.
func loadYAML(path string, v any) error {
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator's configuration, not a request
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	if err := decodeStrict([]byte(os.ExpandEnv(string(data))), v); err != nil {
		return fmt.Errorf("parse %q: %w", path, err)
	}
	return nil
}

func decodeStrict(data []byte, v any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(v)
}

// providerEntries reads the providers file into entries, in the file's order, each decoding itself strictly.
func providerEntries(path string) ([]providers.Entry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator's configuration, not a request
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &document); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	if len(document.Content) == 0 {
		return nil, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse %q: not a mapping", path)
	}
	entries := make([]providers.Entry, 0, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		node := root.Content[i+1]
		entries = append(entries, providers.Entry{
			Key: root.Content[i].Value,
			// Node.Decode cannot refuse unknown fields, a Decoder can.
			Decode: func(v any) error {
				encoded, err := yaml.Marshal(node)
				if err != nil {
					return err
				}
				return decodeStrict(encoded, v)
			},
		})
	}
	return entries, nil
}
