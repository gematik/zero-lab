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

package pep

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

// The JSON texts every reader of this package is held to: a member named twice, a name in another case and a string
// that is not UTF-8 (server rule 28).
var (
	memberTwice   = []byte(`{"sid":"s1","sid":"s2","id":{"sub":"u"},"iat":0,"exp":9999999999}`)
	nameOtherCase = []byte(`{"SID":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`)
	notUTF8       = []byte("{\"sid\":\"s1\",\"id\":{\"sub\":\"\xff\"},\"iat\":0,\"exp\":9999999999}")
)

func TestServerRule28_TokenClaimNamedTwiceIsRefused(t *testing.T) {
	err := validateClaims([]byte(`{"exp":1,"exp":9999999999}`), time.Unix(100, 0), 0, "")
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("err = %v, want a member named twice", err)
	}
}

func TestServerRule28_TokenClaimNameInAnotherCaseIsNotTheClaim(t *testing.T) {
	if err := validateClaims([]byte(`{"EXP":1}`), time.Unix(100, 0), 0, ""); err != nil {
		t.Fatalf("EXP was read as exp: %v", err)
	}
	err := validateClaims([]byte(`{"AUD":"r"}`), time.Unix(100, 0), 0, "r")
	if err == nil || !strings.Contains(err.Error(), "audience does not name the resource") {
		t.Fatalf("err = %v, want AUD not taken for aud", err)
	}
	if got := (&AccessToken{Payload: []byte(`{"cnf":{"JKT":"abc"}}`)}).Thumbprint(); got != "" {
		t.Fatalf("JKT was read as jkt: %q", got)
	}
}

func TestServerRule28_TokenClaimNotUTF8IsRefused(t *testing.T) {
	err := validateClaims([]byte("{\"sub\":\"\xff\"}"), time.Unix(100, 0), 0, "")
	var syntactic *jsontext.SyntacticError
	if !errors.As(err, &syntactic) || !strings.Contains(syntactic.Error(), "invalid UTF-8") {
		t.Fatalf("err = %v, want invalid UTF-8", err)
	}
}

func TestServerRule28_KeySetMemberTwiceOrNotUTF8IsRefused(t *testing.T) {
	_, err := ParseJWKSet([]byte(`{"keys":[],"keys":[]}`))
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("keys twice: err = %v", err)
	}
	_, err = ParseJWKSet([]byte(`{"keys":[{"kty":"EC","kty":"RSA"}]}`))
	if !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Fatalf("kty twice: err = %v", err)
	}
	_, err = ParseJWKSet([]byte("{\"keys\":[],\"x\":\"\xff\"}"))
	if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("not UTF-8: err = %v", err)
	}
}

// "KEYS" is no set: the text is read as a single JWK, which has no kty.
func TestServerRule28_KeySetNameInAnotherCaseIsNotKeys(t *testing.T) {
	set, err := ParseJWKSet([]byte(`{"KEYS":[]}`))
	if err == nil {
		t.Fatalf("KEYS was read as keys: %+v", set)
	}
}

func TestServerRule28_SessionCookieClaimsAreReadExactly(t *testing.T) {
	if _, err := decodeSessionCookieClaims(memberTwice); !errors.Is(err, jsontext.ErrDuplicateName) {
		t.Errorf("member twice: err = %v", err)
	}
	if _, err := decodeSessionCookieClaims(nameOtherCase); !errors.Is(err, json.ErrUnknownName) {
		t.Errorf("name in another case: err = %v", err)
	}
	if _, err := decodeSessionCookieClaims(notUTF8); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("not UTF-8: err = %v", err)
	}
	unknown := []byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999,"admin":true}`)
	if _, err := decodeSessionCookieClaims(unknown); !errors.Is(err, json.ErrUnknownName) {
		t.Errorf("unknown member: err = %v", err)
	}
}

// Sealed with the right key, a snapshot the reader refuses opens no session.
func TestServerRule28_SessionCookieRefusedClaimsOpenNoSession(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	if _, _, ok := OpenSessionCookie(sealTestPayload(t, key, []byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`)), [][]byte{key}, time.Unix(100, 0)); !ok {
		t.Fatal("the well-formed payload does not open")
	}
	for name, payload := range map[string][]byte{"member twice": memberTwice, "name in another case": nameOtherCase, "not UTF-8": notUTF8} {
		if _, _, ok := OpenSessionCookie(sealTestPayload(t, key, payload), [][]byte{key}, time.Unix(100, 0)); ok {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestServerRule28_EnforcerPolicyIsReadExactly(t *testing.T) {
	for name, c := range map[string]struct {
		policy string
		want   error
	}{
		"member twice":         {`{"type":"Scope","scope":"read","scope":"write"}`, jsontext.ErrDuplicateName},
		"name in another case": {`{"type":"AuthorizationDPoP","Nonce_Required":true}`, json.ErrUnknownName},
		"misspelled member":    {`{"type":"AuthorizationDPoP","nonce_require":true}`, json.ErrUnknownName},
	} {
		var h EnforcerHolder
		if err := json.Unmarshal([]byte(c.policy), &h); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	var h EnforcerHolder
	if err := json.Unmarshal([]byte("{\"type\":\"Scope\",\"scope\":\"\xff\"}"), &h); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Errorf("not UTF-8: err = %v", err)
	}
}

func FuzzDecodeSessionCookieClaims(f *testing.F) {
	f.Add([]byte(`{"sid":"s1","id":{"sub":"u"},"iat":0,"exp":9999999999}`))
	f.Add(memberTwice)
	f.Add(nameOtherCase)
	f.Add(notUTF8)
	f.Fuzz(func(t *testing.T, payload []byte) {
		c, err := decodeSessionCookieClaims(payload)
		if err != nil {
			return
		}
		again, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeSessionCookieClaims(again); err != nil {
			t.Fatalf("accepted claims do not read back: %v", err)
		}
	})
}

func FuzzEnforcerHolder(f *testing.F) {
	f.Add([]byte(`{"type":"AllOf","enforcers":[{"type":"AuthorizationBearer"},{"type":"Scope","scope":"read"}]}`))
	f.Add([]byte(`{"type":"Scope","scope":"read","scope":"write"}`))
	f.Add([]byte(`{"TYPE":"Deny"}`))
	f.Add([]byte(`{"type":"AuthorizationDPoP","Nonce_Required":true}`))
	f.Add([]byte("{\"type\":\"Scope\",\"scope\":\"\xff\"}"))
	f.Fuzz(func(_ *testing.T, policy []byte) {
		var h EnforcerHolder
		_ = json.Unmarshal(policy, &h)
	})
}
