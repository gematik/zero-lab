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
	"crypto"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// testRelyingPartyMetadata is what a registered relying party configures (gemSpec_IDP_FD A_23034-02, A_27505).
func testRelyingPartyMetadata() RelyingPartyMetadata {
	return RelyingPartyMetadata{
		ClientName:          "rp",
		OrganizationName:    "Example",
		RedirectURIs:        []string{"https://rp.example/cb"},
		Keywords:            []string{"product_type:zero-lab", "product_type_version:0.0.0"},
		Contacts:            []string{"support@example.invalid"},
		TIFeaturesSupported: &TIFeatures{IDTokenVersionSupported: []string{"1.0.0"}},
	}
}

// testFederationEntity is the federation_entity metadata of a registered relying party.
func testFederationEntity() FederationEntity {
	return FederationEntity{Name: "rp", OrganizationName: "Example"}
}

// literalRelyingParty is a relying party that signs with signer and needs no federation, for tests of signing alone.
func literalRelyingParty(tb testing.TB, signer crypto.Signer) *RelyingParty {
	tb.Helper()
	cfg := &RelyingPartyConfig{
		Subject: "https://rp.example", FedMasterURL: "https://fedmaster.example",
		RelyingParty: testRelyingPartyMetadata(), FederationEntity: testFederationEntity(),
	}
	relyingPartyKeys := keySetOf(newTestKey(tb), "enc-kid")
	metadata := cfg.buildMetadata()
	metadata.OpenidRelyingParty.Jwks = &Jwks{Keys: relyingPartyKeys}
	return &RelyingParty{
		cfg:       cfg,
		fedMaster: cfg.FedMasterURL,
		keys:      Keys{Sign: signer, SignKID: "sign-kid"},
		entityStatement: &EntityStatement{
			Issuer:   cfg.Subject,
			Subject:  cfg.Subject,
			Jwks:     &Jwks{Keys: &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: signer.Public(), KeyID: "sign-kid", Algorithm: "ES256", Use: "sig"}}}},
			Metadata: metadata,
		},
		relyingPartyKeys: relyingPartyKeys,
		signing:          make(chan struct{}, 1),
	}
}

// newTestRelyingParty is a relying party built by New against a federation stub, with the config changed first.
func newTestRelyingParty(t *testing.T, change func(*RelyingPartyConfig)) *RelyingParty {
	t.Helper()
	cfg := testRelyingPartyConfig(t, newFederationStub(t))
	if change != nil {
		change(cfg)
	}
	rp, err := New(t.Context(), cfg, newTestKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// signedClaims signs the relying party's statement and reads its payload as generic JSON.
func signedClaims(t *testing.T, rp *RelyingParty) map[string]any {
	t.Helper()
	signed, err := rp.SignEntityStatement()
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(unverifiedPayload(t, signed), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// member walks claims along the member names given.
func member(claims map[string]any, path ...string) any {
	var value any = claims
	for _, name := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[name]
	}
	return value
}

// The hook runs on a deep copy: what it appends to slices and Extra maps does not accumulate across signings, and the
// relying party's own statement is untouched. Internal invariant of AddEntityStatementHook.
func TestEntityStatementHook(t *testing.T) {
	rp := newTestRelyingParty(t, nil)
	const injected = "https://product.example/as-cb"
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		metadata := es.Metadata.OpenidRelyingParty
		metadata.RedirectURIs = append(metadata.RedirectURIs, injected)
		metadata.Keywords = append(metadata.Keywords, "added")
		metadata.Contacts = append(metadata.Contacts, "added@rp.example")
		if metadata.Extra == nil {
			metadata.Extra = map[string]json.RawMessage{}
		}
		metadata.Extra["added"] = json.RawMessage(`true`)
		es.Metadata.Extra = map[string]json.RawMessage{"added_entity_type": json.RawMessage(`{}`)}
		return nil
	})

	first := signedClaims(t, rp)
	redirects, _ := member(first, "metadata", "openid_relying_party", "redirect_uris").([]any)
	if !slices.Contains(redirects, any(injected)) {
		t.Fatalf("hook redirect not in served entity statement: %v", redirects)
	}
	second := signedClaims(t, rp)
	for _, name := range []string{"redirect_uris", "keywords", "contacts"} {
		before, _ := member(first, "metadata", "openid_relying_party", name).([]any)
		after, _ := member(second, "metadata", "openid_relying_party", name).([]any)
		if len(before) != len(after) {
			t.Errorf("%s accumulated across signings: %d then %d", name, len(before), len(after))
		}
	}
	base := rp.entityStatement.Metadata
	if len(base.OpenidRelyingParty.RedirectURIs) != 1 || len(base.OpenidRelyingParty.Keywords) != 2 ||
		len(base.OpenidRelyingParty.Contacts) != 1 || base.OpenidRelyingParty.Extra != nil || base.Extra != nil {
		t.Errorf("base entity statement mutated by hook: %+v", base.OpenidRelyingParty)
	}
}

// A caller adds whole entity types and members oidf does not know through the hook, and they are signed as given.
func TestEntityStatementHook_AddsAWholeEntityType(t *testing.T) {
	rp := newTestRelyingParty(t, nil)
	rp.AddEntityStatementHook(func(es *EntityStatement) error {
		es.Metadata.Extra = map[string]json.RawMessage{
			"oauth_authorization_server": json.RawMessage(`{"issuer":"https://rp.example","grant_types_supported":["authorization_code"]}`),
		}
		es.Metadata.OpenidRelyingParty.Extra = map[string]json.RawMessage{"added_member": json.RawMessage(`"value"`)}
		es.Metadata.FederationEntity.Extra = map[string]json.RawMessage{"added_member": json.RawMessage(`1`)}
		return nil
	})
	claims := signedClaims(t, rp)
	if issuer := member(claims, "metadata", "oauth_authorization_server", "issuer"); issuer != "https://rp.example" {
		t.Errorf("oauth_authorization_server = %v", member(claims, "metadata", "oauth_authorization_server"))
	}
	if value := member(claims, "metadata", "openid_relying_party", "added_member"); value != "value" {
		t.Errorf("openid_relying_party.added_member = %v", value)
	}
	if value := member(claims, "metadata", "federation_entity", "added_member"); value != float64(1) {
		t.Errorf("federation_entity.added_member = %v", value)
	}
	if member(claims, "metadata", "openid_relying_party", "client_name") != "rp" {
		t.Error("the typed members are gone beside the extra ones")
	}
}

// A hook that fails fails the signing, and nothing half-built is signed. Internal invariant of AddEntityStatementHook,
// servers.md rule 16.
func TestEntityStatementHook_AFailingHookFailsSigning(t *testing.T) {
	rp := newTestRelyingParty(t, nil)
	refused := errors.New("registry unavailable")
	rp.AddEntityStatementHook(func(*EntityStatement) error { return refused })
	if signed, err := rp.SignEntityStatement(); !errors.Is(err, refused) || signed != nil {
		t.Fatalf("signed %q, err = %v", signed, err)
	}
}
