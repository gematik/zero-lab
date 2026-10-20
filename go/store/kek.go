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

package store

import (
	"bytes"
	"encoding/base64"
)

// ParseKEKFile parses the content of a key file (STORE-094). mode is its POSIX mode, or
// negative where the platform has none; the caller reads both.
func ParseKEKFile(content []byte, mode int) ([32]byte, error) {
	var kek [32]byte
	if mode >= 0 && mode&0o077 != 0 {
		return kek, ErrInsecurePermissions
	}
	text := bytes.TrimSuffix(content, []byte("\n"))
	if len(text) != 44 {
		return kek, fail(CodeMalformed, "key file")
	}
	// Strict: one encoding per key, no padding bits set (RFC 4648 §3.5).
	b, err := base64.StdEncoding.Strict().DecodeString(string(text))
	if err != nil || len(b) != 32 {
		return kek, fail(CodeMalformed, "key file")
	}
	copy(kek[:], b)
	clear(b)
	return kek, nil
}
