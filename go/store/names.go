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
	"crypto/hmac"
	"crypto/sha256"
)

// Limits of STORE-030, STORE-033 and STORE-054.
const (
	MaxID      = 4096
	MaxTags    = 16
	MaxPayload = 16 << 20
)

// Name is what a backend stores in place of an id (STORE-030).
type Name [32]byte

// Tag is a blind-index tag: the field name in clear and the hash of its value (STORE-034).
type Tag struct {
	Field string
	Tag   [32]byte
}

func lower(c byte) bool { return c >= 'a' && c <= 'z' }
func digit(c byte) bool { return c >= '0' && c <= '9' }

// ValidNamespace reports whether ns has the syntax of STORE-020.
func ValidNamespace(ns string) bool {
	if len(ns) < 1 || len(ns) > 64 || (!lower(ns[0]) && !digit(ns[0])) {
		return false
	}
	for i := 0; i < len(ns); i++ {
		c := ns[i]
		if !lower(c) && !digit(c) && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// ValidField reports whether f has the syntax of STORE-033.
func ValidField(f string) bool {
	if len(f) < 1 || len(f) > 32 {
		return false
	}
	for i := 0; i < len(f); i++ {
		if c := f[i]; !lower(c) && !digit(c) && c != '_' {
			return false
		}
	}
	return true
}

// ValidKid reports whether kid has the syntax of STORE-051.
func ValidKid(kid string) bool {
	if len(kid) < 1 || len(kid) > 64 {
		return false
	}
	for i := 0; i < len(kid); i++ {
		if c := kid[i]; c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func checkNamespace(ns string) error {
	if !ValidNamespace(ns) {
		return fail(CodeInvalidArgument, "namespace")
	}
	return nil
}

func nameInput(ns string, id []byte) []byte {
	return appendLP(appendLP(nil, []byte(ns)), id)
}

func tagInput(ns, field string, value []byte) []byte {
	return appendLP(appendLP(appendLP(nil, []byte(ns)), []byte(field)), value)
}

func hmacSHA256(key, msg []byte) (out [32]byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	copy(out[:], m.Sum(nil))
	return out
}

func sha256Labelled(label string, msg []byte) [32]byte {
	return sha256.Sum256(append(appendLP(nil, []byte(label)), msg...))
}

func checkID(ns string, id []byte) error {
	if err := checkNamespace(ns); err != nil {
		return err
	}
	if len(id) > MaxID {
		return fail(CodeLimitExceeded, "id")
	}
	return nil
}

func checkTag(ns, field string, value []byte) error {
	if err := checkNamespace(ns); err != nil {
		return err
	}
	if !ValidField(field) {
		return fail(CodeInvalidArgument, "field")
	}
	if len(value) > MaxID {
		return fail(CodeLimitExceeded, "tag value")
	}
	return nil
}

// PlainName is the name of id in a plain namespace (STORE-032).
func PlainName(ns string, id []byte) (Name, error) {
	if err := checkID(ns, id); err != nil {
		return Name{}, err
	}
	return Name(sha256Labelled("zl-store/1/plain-name", nameInput(ns, id))), nil
}

// PlainTag is a tag in a plain namespace (STORE-034).
func PlainTag(ns, field string, value []byte) (Tag, error) {
	if err := checkTag(ns, field, value); err != nil {
		return Tag{}, err
	}
	return Tag{Field: field, Tag: sha256Labelled("zl-store/1/plain-tag", tagInput(ns, field, value))}, nil
}
