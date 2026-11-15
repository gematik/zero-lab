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
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// ErrEntityStatement is an entity statement the relying party refuses to sign.
var ErrEntityStatement = errors.New("entity statement refused")

// MarshalJSON writes the typed members and the Extra ones.
func (m *Metadata) MarshalJSON() ([]byte, error) {
	type typed Metadata
	return withExtra((*typed)(m), m.Extra, "metadata")
}

// MarshalJSON writes the typed members and the Extra ones.
func (m *OpenIDRelyingPartyMetadata) MarshalJSON() ([]byte, error) {
	type typed OpenIDRelyingPartyMetadata
	return withExtra((*typed)(m), m.Extra, "openid_relying_party")
}

// MarshalJSON writes the typed members and the Extra ones.
func (m *FederationEntityMetadata) MarshalJSON() ([]byte, error) {
	type typed FederationEntityMetadata
	return withExtra((*typed)(m), m.Extra, "federation_entity")
}

// statementJSON writes what the relying party signs and serves byte for byte as encoding/json v1 did, so that the
// same statement keeps its signature input and ETag: maps sorted by name, a nil slice as null, and <, >, &, U+2028
// and U+2029 escaped, in raw values too, whose escapes are kept as written.
var statementJSON = json.JoinOptions(
	json.Deterministic(true),
	json.FormatNilSliceAsNull(true),
	json.FormatNilMapAsNull(true),
	jsontext.EscapeForHTML(true),
	jsontext.EscapeForJS(true),
	jsontext.PreserveRawStrings(true),
)

// withExtra marshals the typed value of the object named where and adds the extra members. An extra member that
// shadows a typed one, even one left out as empty, is an error, and so is one that is not valid JSON as RFC 7493 has
// it, with a member name twice or invalid UTF-8: what is signed has to be what the typed fields say, and read the same
// by every member of the federation. This package reads names exactly, but names are compared without case here: a
// member whose decoder matches names without case, as encoding/json v1 does, would take the extra member for the
// typed one.
func withExtra(value any, extra map[string]jsontext.Value, where string) ([]byte, error) {
	data, err := json.Marshal(value, statementJSON)
	if err != nil || len(extra) == 0 {
		return data, err
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, err
	}
	typed := memberNames(reflect.TypeOf(value).Elem())
	for name, raw := range extra {
		if slices.ContainsFunc(typed, func(member string) bool { return strings.EqualFold(member, name) }) {
			return nil, fmt.Errorf("%w: %s member %q shadows a typed member", ErrEntityStatement, where, name)
		}
		if !jsontext.Value(raw).IsValid() {
			return nil, fmt.Errorf("%w: %s member %q is not valid JSON", ErrEntityStatement, where, name)
		}
		members[name] = raw
	}
	return json.Marshal(members, statementJSON)
}

// memberNames are the JSON member names of a struct's fields.
func memberNames(structType reflect.Type) []string {
	var names []string
	for field := range structType.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		switch name {
		case "-":
		case "":
			names = append(names, field.Name)
		default:
			names = append(names, name)
		}
	}
	return names
}

// clone copies the statement so deeply that a hook changing the copy, its slices or its Extra members, leaves the
// original as it was. openid_provider is not part of a relying party's statement and is shared.
func (es *EntityStatement) clone() *EntityStatement {
	clone := *es
	clone.AuthorityHints = slices.Clone(es.AuthorityHints)
	clone.Jwks = es.Jwks.clone()
	if es.Metadata != nil {
		metadata := *es.Metadata
		metadata.Extra = cloneExtra(es.Metadata.Extra)
		if rp := es.Metadata.OpenidRelyingParty; rp != nil {
			metadata.OpenidRelyingParty = rp.clone()
		}
		if entity := es.Metadata.FederationEntity; entity != nil {
			metadata.FederationEntity = entity.clone()
		}
		clone.Metadata = &metadata
	}
	return &clone
}

func (m *OpenIDRelyingPartyMetadata) clone() *OpenIDRelyingPartyMetadata {
	clone := *m
	clone.Jwks = m.Jwks.clone()
	clone.Keywords = slices.Clone(m.Keywords)
	clone.Contacts = slices.Clone(m.Contacts)
	clone.RedirectURIs = slices.Clone(m.RedirectURIs)
	clone.ResponseTypes = slices.Clone(m.ResponseTypes)
	clone.ClientRegistrationTypes = slices.Clone(m.ClientRegistrationTypes)
	clone.GrantTypes = slices.Clone(m.GrantTypes)
	clone.DefaultACRValues = slices.Clone(m.DefaultACRValues)
	if m.TIFeaturesSupported != nil {
		clone.TIFeaturesSupported = &TIFeatures{IDTokenVersionSupported: slices.Clone(m.TIFeaturesSupported.IDTokenVersionSupported)}
	}
	clone.Extra = cloneExtra(m.Extra)
	return &clone
}

func (m *FederationEntityMetadata) clone() *FederationEntityMetadata {
	clone := *m
	clone.Contacts = slices.Clone(m.Contacts)
	clone.Extra = cloneExtra(m.Extra)
	return &clone
}

// clone copies the set's list of keys; the keys themselves are shared.
func (j *Jwks) clone() *Jwks {
	if j == nil || j.Keys == nil {
		return j
	}
	return &Jwks{Keys: &jose.JSONWebKeySet{Keys: slices.Clone(j.Keys.Keys)}}
}

func cloneExtra(extra map[string]jsontext.Value) map[string]jsontext.Value {
	if extra == nil {
		return nil
	}
	clone := maps.Clone(extra)
	for name, raw := range clone {
		clone[name] = bytes.Clone(raw)
	}
	return clone
}

// hasMemberD reports whether a member named d is anywhere in the JSON payload, at any depth: d is where a JWK keeps
// its private part (RFC 7518 sections 6.2.2.1 and 6.3.2.1).
func hasMemberD(payload []byte) (bool, error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(payload))
	for {
		// Inside an object, a name comes at every even position.
		kind, length := decoder.StackIndex(decoder.StackDepth())
		atName := kind == '{' && length%2 == 0 && decoder.PeekKind() != '}'
		token, err := decoder.ReadToken()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if atName && token.String() == "d" {
			return true, nil
		}
	}
}
