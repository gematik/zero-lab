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

package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
)

// testdata/legacy_session.json was made by the code of commit a11372a, the last one built on the previous JOSE
// library, from its minting paths: a snapshot, session DPoP keys (with coordinates that have a leading zero byte) and
// a client assertion.
type legacySession struct {
	SnapshotKey string         `json:"snapshot_key_b64"`
	Snapshot    string         `json:"snapshot"`
	SID         string         `json:"sid"`
	Identity    map[string]any `json:"identity"`
	DPoPKeys    []struct {
		Note string          `json:"note"`
		JWK  json.RawMessage `json:"jwk"`
		JKT  string          `json:"jkt"`
	} `json:"dpop_keys"`
	ClientSigningJWK json.RawMessage `json:"client_signing_jwk"`
	ClientAssertion  string          `json:"client_assertion"`
}

func readLegacySession(t *testing.T) legacySession {
	t.Helper()
	raw, err := os.ReadFile("testdata/legacy_session.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture legacySession
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestLegacySnapshotFromOldMintStillOpens(t *testing.T) {
	fixture := readLegacySession(t)
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(fixture.SnapshotKey), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := newSnapshotter(path, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := snap.open(fixture.Snapshot)
	if !ok {
		t.Fatal("a snapshot sealed by the old code does not open")
	}
	if claims.SID != fixture.SID || !reflect.DeepEqual(claims.Identity, fixture.Identity) {
		t.Fatalf("claims = %+v", claims)
	}
}

// RFC 7516 Section 7.1: the compact header of a snapshot is the old one, so a verifier not yet upgraded opens it.
func TestSnapshotHeaderIsTheOldOne(t *testing.T) {
	fixture := readLegacySession(t)
	snap, err := newSnapshotter(writeKeyFile(t, "key"), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	minted, err := snap.mint("s", map[string]any{"sub": "u"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Split(minted, ".")[0], strings.Split(fixture.Snapshot, ".")[0]; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

// Sessions at rest hold these keys, and the tokens issued for them are bound to these thumbprints (RFC 7638).
func TestLegacySessionDPoPKeysStillSignAndKeepTheirThumbprints(t *testing.T) {
	for _, c := range readLegacySession(t).DPoPKeys {
		t.Run(c.Note, func(t *testing.T) {
			key, err := parseSessionDPoPKey(c.JWK)
			if err != nil {
				t.Fatal(err)
			}
			if key.Thumbprint() != c.JKT {
				t.Fatalf("thumbprint = %q, want %q", key.Thumbprint(), c.JKT)
			}
			req, err := http.NewRequest(http.MethodGet, "https://api.example/protected", nil)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := (sessionKeySigner{}).dpopProof(req, "the-access-token", key)
			if err != nil {
				t.Fatal(err)
			}
			verifyDPoP(t, proof, dpop.Request{
				Method:      http.MethodGet,
				URI:         "https://api.example/protected",
				AccessToken: "the-access-token",
				Thumbprint:  c.JKT,
			})
		})
	}
}

func TestSessionDPoPKeyIsStoredInTheOldForm(t *testing.T) {
	fixture := readLegacySession(t)
	_, js, err := newSessionDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := memberNames(t, js), memberNames(t, fixture.DPoPKeys[0].JWK); !reflect.DeepEqual(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
}

func TestPublicJWKIsNotASessionDPoPKey(t *testing.T) {
	public := []byte(`{"crv":"P-256","kty":"EC","x":"CSe6WWOsFaUSjp437htjVBkDdF5LRj_ZvBfxQ4BecH4","y":"rhz8yAOajNwAH3DTujwepcsUQI-cBeSMGyCuByhbh-4"}`)
	if _, err := parseSessionDPoPKey(public); err == nil {
		t.Fatal("a public key was taken as a signing key")
	}
}

func memberNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The PDP decodes aud as a list and reads kid and cnf.jkt: the assertion keeps the old header and members.
func TestClientAssertionKeepsTheOldHeaderAndClaims(t *testing.T) {
	fixture := readLegacySession(t)
	signing := new(jose.JSONWebKey)
	if err := json.Unmarshal(fixture.ClientSigningJWK, signing); err != nil {
		t.Fatal(err)
	}
	b := &pdpBackend{
		cfg:  PDPConfig{ASIssuer: "https://as.example", ClientID: "pep-client", SigningKey: signing},
		meta: asMetadata{Issuer: "https://as.example"},
	}
	assertion, err := b.clientAssertion(context.Background(), &Session{ID: "s1", DPoPKeyJWK: fixture.DPoPKeys[0].JWK})
	if err != nil {
		t.Fatal(err)
	}
	newParts, oldParts := strings.Split(assertion, "."), strings.Split(fixture.ClientAssertion, ".")
	if newParts[0] != oldParts[0] {
		t.Fatalf("header = %q, want %q", newParts[0], oldParts[0])
	}
	decode := func(segment string) map[string]any {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		return claims
	}
	newClaims, oldClaims := decode(newParts[1]), decode(oldParts[1])
	for _, varying := range []string{"iat", "exp", "jti"} {
		if newClaims[varying] == nil {
			t.Fatalf("no %s", varying)
		}
		delete(newClaims, varying)
		delete(oldClaims, varying)
	}
	if !reflect.DeepEqual(newClaims, oldClaims) {
		t.Fatalf("claims = %v, want %v", newClaims, oldClaims)
	}
}
