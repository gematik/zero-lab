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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// gemSpec_IDP_FedMaster A_28857: exp − iat of the statement is at most 24 hours.
func TestA_28857_TheStatementLivesAtMostADay(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	rp := newTestRelyingParty(t, func(cfg *RelyingPartyConfig) { cfg.Clock = func() time.Time { return now } })
	claims := signedClaims(t, rp)
	issuedAt, expiresAt := claims["iat"].(float64), claims["exp"].(float64)
	if expiresAt-issuedAt > 86400 {
		t.Errorf("exp − iat = %v s", expiresAt-issuedAt)
	}
	if int64(issuedAt) > now.Unix() || int64(expiresAt) <= now.Unix() {
		t.Errorf("iat %v exp %v around %d", issuedAt, expiresAt, now.Unix())
	}
}

// OpenID Federation 1.1 section 3: an entity configuration is a statement an entity makes about itself, iss equal to
// sub. A hook cannot rename the entity: iss and sub are set after the hooks.
func TestOIDF_EntityConfiguration_IssEqualsSub(t *testing.T) {
	rp := newTestRelyingParty(t, nil)
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		es.Issuer, es.Subject = "https://other.example", "https://other.example"
		return nil
	})
	if claims := signedClaims(t, rp); claims["iss"] != "https://rp.example" || claims["sub"] != "https://rp.example" {
		t.Errorf("iss %v sub %v", claims["iss"], claims["sub"])
	}
}

// OpenID Federation 1.1 section 3: the entity configuration is signed with a key of its own jwks, found by the header's
// kid.
func TestOIDF_EntityConfiguration_TheSigningKeyIsInJwks(t *testing.T) {
	for name, change := range map[string]func(*EntityStatement){
		"no jwks":     func(es *EntityStatement) { es.Jwks = nil },
		"kid missing": func(es *EntityStatement) { es.Jwks.Keys.Keys[0].KeyID = "other" },
		"another key": func(es *EntityStatement) { es.Jwks.Keys.Keys[0].Key = newTestKey(t).Public() },
	} {
		t.Run(name, func(t *testing.T) {
			rp := newTestRelyingParty(t, nil)
			rp.AddEntityStatementHook(func(es *EntityStatement) error {
				change(es)
				return nil
			})
			if _, err := rp.SignEntityStatement(); !errors.Is(err, ErrEntityStatement) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// Servers rule 17: a member added through Extra that would shadow a typed one, or is not JSON at all, makes the
// statement say something other than its fields; signing refuses it instead of guessing which one counts.
func TestServerRule17_AnExtraMemberThatShadowsATypedOneIsRefused(t *testing.T) {
	for name, change := range map[string]func(*Metadata){
		"openid_relying_party member": func(m *Metadata) {
			m.OpenidRelyingParty.Extra = map[string]json.RawMessage{"client_name": json.RawMessage(`"other"`)}
		},
		"empty typed member": func(m *Metadata) {
			m.OpenidRelyingParty.Extra = map[string]json.RawMessage{"logo_uri": json.RawMessage(`"https://other.example/logo"`)}
		},
		"member in other case": func(m *Metadata) {
			m.OpenidRelyingParty.Extra = map[string]json.RawMessage{"JWKS": json.RawMessage(`{"keys":[]}`)}
		},
		"empty member in other case": func(m *Metadata) {
			m.OpenidRelyingParty.Extra = map[string]json.RawMessage{"Signed_jwks_uri": json.RawMessage(`"https://other.example/jwks"`)}
		},
		"federation_entity member": func(m *Metadata) {
			m.FederationEntity.Extra = map[string]json.RawMessage{"name": json.RawMessage(`"other"`)}
		},
		"entity type": func(m *Metadata) {
			m.Extra = map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{}`)}
		},
		"invalid JSON": func(m *Metadata) {
			m.OpenidRelyingParty.Extra = map[string]json.RawMessage{"added": json.RawMessage(`{"open":`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rp := newTestRelyingParty(t, nil)
			rp.AddEntityStatementHook(func(es *EntityStatement) error {
				change(es.Metadata)
				return nil
			})
			if _, err := rp.SignEntityStatement(); !errors.Is(err, ErrEntityStatement) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// Keys rule 1: no private key part leaves the relying party, also not through a hook that hands a private JWK or a
// member named d somewhere deep in an added entity type.
func TestKeysRule1_NoPrivateKeyPartIsPublished(t *testing.T) {
	rp := newTestRelyingParty(t, nil)
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	if private, err := hasMemberD(unverifiedPayload(t, signed)); err != nil || private {
		t.Fatalf("the statement has a member d: %v %v", private, err)
	}
	for name, change := range map[string]func(*EntityStatement){
		"private JWK": func(es *EntityStatement) {
			es.Jwks.Keys.Keys = append(es.Jwks.Keys.Keys, jose.JSONWebKey{Key: newTestKey(t), KeyID: "private"})
		},
		"deep member": func(es *EntityStatement) {
			es.Metadata.Extra = map[string]json.RawMessage{"added": json.RawMessage(`{"list":[1,{"keys":[{"kty":"EC","d":"x"}]}]}`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rp := newTestRelyingParty(t, nil)
			rp.AddEntityStatementHook(func(es *EntityStatement) error {
				change(es)
				return nil
			})
			if _, err := rp.SignEntityStatement(); !errors.Is(err, ErrEntityStatement) || !strings.Contains(err.Error(), "private") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// hasMemberD tells member names from string values at every depth. Internal invariant of the private key check.
func TestHasMemberDTellsNamesFromValues(t *testing.T) {
	for payload, want := range map[string]bool{
		`{"d":1}`:                      true,
		`{"a":"d"}`:                    false,
		`["d"]`:                        false,
		`{"a":["d",{"b":{}},{"d":0}]}`: true,
		`{"a":{},"b":[],"c":"d"}`:      false,
		`{"a":[{}],"d":null}`:          true,
		`"d"`:                          false,
	} {
		if got, err := hasMemberD([]byte(payload)); err != nil || got != want {
			t.Errorf("%s: %v %v", payload, got, err)
		}
	}
	if _, err := hasMemberD([]byte(`{"a":`)); err == nil {
		t.Error("broken JSON passed")
	}
}

// gemSpec_IDP_FD A_23034-02 Tabelle 4 (*): the openid_relying_party metadata carries either signed_jwks_uri or jwks.
func TestA_23034_02_JwksOrSignedJwksURINotBoth(t *testing.T) {
	rp := newTestRelyingParty(t, func(cfg *RelyingPartyConfig) { cfg.RelyingParty.SignedJwksURI = "https://rp.example/jwks" })
	metadata, _ := member(signedClaims(t, rp), "metadata", "openid_relying_party").(map[string]any)
	if _, inline := metadata["jwks"]; inline || metadata["signed_jwks_uri"] != "https://rp.example/jwks" {
		t.Errorf("metadata = %v", metadata)
	}
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		es.Metadata.OpenidRelyingParty.Jwks = &Jwks{Keys: rp.relyingPartyKeys}
		return nil
	})
	if _, err := rp.SignEntityStatement(); !errors.Is(err, ErrEntityStatement) || !strings.Contains(err.Error(), "signed_jwks_uri") {
		t.Errorf("err = %v", err)
	}
}

// refusedBy signs with the hook given and asserts the refusal names the member.
func refusedBy(t *testing.T, change func(*EntityStatement), member string) {
	t.Helper()
	rp := newTestRelyingParty(t, nil)
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		change(es)
		return nil
	})
	if signed, err := rp.SignEntityStatement(); !errors.Is(err, ErrEntityStatement) || !strings.Contains(err.Error(), member) {
		t.Errorf("signed %d bytes, err = %v", len(signed), err)
	}
}

// gemSpec_IDP_FD A_23034-02 Tabelle 4: the openid_relying_party metadata is there, with client_name and
// organization_name in the Wertebereich ^[ à-üÀ-Ü ß\w\ \-\.\+\*\/]{1,128}$, keywords naming the product type and its
// version, and a contact. A statement without them is not signed.
func TestA_23034_02_ARelyingPartyWithoutTheRequiredMembersIsRefused(t *testing.T) {
	for name, test := range map[string]struct {
		change func(*OpenIDRelyingPartyMetadata)
		member string
	}{
		"empty client_name":             {func(m *OpenIDRelyingPartyMetadata) { m.ClientName = "" }, "client_name"},
		"client_name with a colon":      {func(m *OpenIDRelyingPartyMetadata) { m.ClientName = "https://rp.example" }, "client_name"},
		"client_name too long":          {func(m *OpenIDRelyingPartyMetadata) { m.ClientName = strings.Repeat("ä", 129) }, "client_name"},
		"no organization_name":          {func(m *OpenIDRelyingPartyMetadata) { m.OrganizationName = "" }, "organization_name"},
		"organization_name with U+2028": {func(m *OpenIDRelyingPartyMetadata) { m.OrganizationName = "Société\u2028" }, "organization_name"},
		"no keywords":                   {func(m *OpenIDRelyingPartyMetadata) { m.Keywords = nil }, "product_type:"},
		"no product type version":       {func(m *OpenIDRelyingPartyMetadata) { m.Keywords = []string{"product_type:zero-lab"} }, "product_type_version:"},
		"an empty product type":         {func(m *OpenIDRelyingPartyMetadata) { m.Keywords = []string{"product_type:", "product_type_version:1"} }, "product_type:"},
		"no contacts":                   {func(m *OpenIDRelyingPartyMetadata) { m.Contacts = nil }, "contacts"},
		"neither jwks nor the URI":      {func(m *OpenIDRelyingPartyMetadata) { m.Jwks = nil }, "signed_jwks_uri"},
	} {
		t.Run(name, func(t *testing.T) {
			refusedBy(t, func(es *EntityStatement) { test.change(es.Metadata.OpenidRelyingParty) }, test.member)
		})
	}
	t.Run("no openid_relying_party", func(t *testing.T) {
		refusedBy(t, func(es *EntityStatement) { es.Metadata.OpenidRelyingParty = nil }, "openid_relying_party")
	})
}

// The Wertebereich of Tabelle 4 names umlauts and ß beside ASCII word characters.
func TestA_23034_02_UmlautsAndSharpSAreInTheWertebereich(t *testing.T) {
	rp := newTestRelyingParty(t, func(cfg *RelyingPartyConfig) {
		cfg.RelyingParty.ClientName = "Größe Äöü-Dienst +*/."
		cfg.RelyingParty.OrganizationName = "Straße Müller GmbH"
	})
	if claims := signedClaims(t, rp); member(claims, "metadata", "openid_relying_party", "client_name") != "Größe Äöü-Dienst +*/." {
		t.Errorf("client_name = %v", member(claims, "metadata", "openid_relying_party", "client_name"))
	}
}

// gemSpec_IDP_FD A_27505: ti_features_supported names the ID token versions supported, from "1.0.0" and "2.0.0".
func TestA_27505_TIFeaturesSupportedIsRequired(t *testing.T) {
	for name, features := range map[string]*TIFeatures{
		"missing":       nil,
		"empty":         {},
		"other version": {IDTokenVersionSupported: []string{"3.0.0"}},
		"twice":         {IDTokenVersionSupported: []string{"1.0.0", "1.0.0"}},
	} {
		t.Run(name, func(t *testing.T) {
			refusedBy(t, func(es *EntityStatement) { es.Metadata.OpenidRelyingParty.TIFeaturesSupported = features }, "id_token_version_supported")
		})
	}
}

// gemSpec_IDP_FD A_23034-02 Tabelle 3: the statement's jwks holds the signing key only; A_23196: every published key
// is a public P-256 key.
func TestA_23034_02_JwksHoldsTheSigningKeyOnly(t *testing.T) {
	refusedBy(t, func(es *EntityStatement) {
		es.Jwks.Keys.Keys = append(es.Jwks.Keys.Keys, jose.JSONWebKey{Key: []byte("0123456789abcdef"), KeyID: "oct"})
	}, "private key")
	refusedBy(t, func(es *EntityStatement) {
		es.Jwks.Keys.Keys = append(es.Jwks.Keys.Keys, jose.JSONWebKey{Key: newTestKey(t).Public(), KeyID: "next", Use: "sig"})
	}, "another key than the signing key")
	refusedBy(t, func(es *EntityStatement) {
		keys := es.Metadata.OpenidRelyingParty.Jwks.Keys
		keys.Keys = append(keys.Keys, jose.JSONWebKey{Key: []byte("0123456789abcdef"), KeyID: "oct"})
	}, "openid_relying_party jwks")
}

// gemSpec_IDP_FD A_23034-02: logo_uri, the one optional member a deployment may leave out, is not written empty.
func TestA_23034_02_AnOptionalMemberLeftOutIsNotWritten(t *testing.T) {
	metadata, _ := member(signedClaims(t, newTestRelyingParty(t, nil)), "metadata", "openid_relying_party").(map[string]any)
	for _, name := range []string{"logo_uri", "signed_jwks_uri"} {
		if value, ok := metadata[name]; ok {
			t.Errorf("%s = %v", name, value)
		}
	}
}

// A statement too large for a member to take is not signed. Internal invariant of signing, servers.md rule 2.
func TestServerRule2_AStatementLargerThanItsBoundIsRefused(t *testing.T) {
	refusedBy(t, func(es *EntityStatement) {
		es.Metadata.Extra = map[string]json.RawMessage{"large": json.RawMessage(`"` + strings.Repeat("x", maxStatementBytes) + `"`)}
	}, "more than")
}

// gemSpec_IDP_FD A_23034-02 Tabelle 4 and A_27505: keywords, contacts, organization_name and ti_features_supported are
// published as configured.
func TestA_27505_TheFeaturesAndInformationalMembersArePublished(t *testing.T) {
	rp := newTestRelyingParty(t, func(cfg *RelyingPartyConfig) {
		cfg.RelyingParty.OrganizationName = "Example GmbH"
		cfg.RelyingParty.Keywords = []string{"product_type:example", "product_type_version:1.0.0"}
		cfg.RelyingParty.Contacts = []string{"support@rp.example"}
		cfg.RelyingParty.TIFeaturesSupported = &TIFeatures{IDTokenVersionSupported: []string{"1.0.0", "2.0.0"}}
		cfg.FederationEntity.OrganizationName = "Example GmbH"
	})
	claims := signedClaims(t, rp)
	encoded, err := json.Marshal(member(claims, "metadata"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata Metadata
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		t.Fatal(err)
	}
	relyingParty := metadata.OpenidRelyingParty
	if relyingParty.OrganizationName != "Example GmbH" || len(relyingParty.Keywords) != 2 ||
		len(relyingParty.Contacts) != 1 || relyingParty.TIFeaturesSupported == nil ||
		len(relyingParty.TIFeaturesSupported.IDTokenVersionSupported) != 2 {
		t.Errorf("openid_relying_party = %+v", relyingParty)
	}
	if metadata.FederationEntity.OrganizationName != "Example GmbH" {
		t.Errorf("federation_entity = %+v", metadata.FederationEntity)
	}
}

// parseEntityStatement reads statements of other entities, so it gets arbitrary bytes; a statement it accepts
// marshals again.
func FuzzParseEntityStatement(f *testing.F) {
	f.Add([]byte(`{"iss":"https://op.example","sub":"https://op.example","iat":1,"exp":2,"jwks":{"keys":[]},"metadata":{"openid_provider":{"issuer":"https://op.example"}}}`))
	f.Add([]byte(`{"metadata":{"openid_relying_party":{"client_name":"rp","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs","y":"XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw"}]}},"federation_entity":{"name":"x"}}}`))
	f.Add([]byte(`{"metadata":{"federation_entity":{"federation_fetch_endpoint":"https://m.example/fetch","idp_list_endpoint":"https://m.example/list"}},"authority_hints":["https://m.example"]}`))
	f.Add([]byte(`{"jwks":{"keys":[{"kty":"EC","crv":"P-256","d":"x"}]}}`))
	f.Add([]byte(`{"iat":1e400,"exp":-1,"metadata":null,"jwks":null}`))
	f.Add([]byte(`{"metadata":{"openid_relying_party":{"ti_features_supported":{"id_token_version_supported":["1.0.0"]},"d":1}}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		statement, err := parseEntityStatement(payload)
		if err != nil {
			return
		}
		if _, err := json.Marshal(statement); err != nil {
			t.Fatalf("an accepted statement does not marshal: %v", err)
		}
	})
}
