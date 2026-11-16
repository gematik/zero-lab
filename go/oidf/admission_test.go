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
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Servers rule 2 and gemSpec_IDP_FedMaster Tabelle 8: only the IDPs on the master's signed list are asked. The issuer
// comes from a request, so nothing is fetched at or about it before it is found on the list.
func TestFedMaster_IdPList_AnIDPNotOnItIsRefusedBeforeAnyFetch(t *testing.T) {
	stub := newFederationStub(t)
	rp := stub.relyingParty(t)
	counter := stub.countFetches()
	for name, issuer := range map[string]string{
		"not listed":           stub.URL + "/other",
		"a trailing slash":     stub.URL + "/op/",
		"another case":         strings.ToUpper(stub.URL[:5]) + stub.URL[5:] + "/op",
		"no entity identifier": "http://op.example",
	} {
		if _, err := rp.Client(t.Context(), issuer); !errors.Is(err, ErrIDPNotAdmitted) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, path := range []string{"/fetch", "/other/.well-known/openid-federation", "/op/.well-known/openid-federation", "/op/jwks"} {
		if n := counter.count(path); n != 0 {
			t.Errorf("%s fetched %d times", path, n)
		}
	}
	if _, err := rp.Client(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatalf("a listed IDP: %v", err)
	}
}

// An IDP the master has taken off its list is no longer admitted, even with its statement kept.
func TestFedMaster_IdPList_AnIDPTakenOffItIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	rp := stub.relyingParty(t)
	if _, err := rp.Client(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
	stub.idpList = signJWS(t, stub.masterKey, "master", map[string]any{
		"iss": stub.URL, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "idp_entity": []any{},
	})
	rp.federation = stub.federation(t)
	if _, err := rp.Client(t.Context(), stub.URL+"/op"); !errors.Is(err, ErrIDPNotAdmitted) {
		t.Fatalf("err = %v", err)
	}
}

// OpenID Federation 1.1 section 5.1.3: a login goes to an entity whose statement describes an openid_provider, and
// OpenID Connect Discovery 1.0 section 4.3: that metadata names the issuer it was resolved as.
func TestOIDF_AnEntityWithoutOpenIDProviderMetadataIsRefused(t *testing.T) {
	for name, overrides := range map[string]map[string]any{
		"no openid_provider":        {"metadata": map[string]any{"federation_entity": map[string]any{"name": "op"}}},
		"another issuer":            {"issuer": "https://other.example"},
		"signed_jwks_uri not https": {"signed_jwks_uri": "http://op.example/jwks"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := newFederationStub(t)
			claims := stub.opClaims(overrides)
			if metadata, ok := overrides["metadata"]; ok {
				claims["metadata"] = metadata
			}
			stub.opStatement = signJWS(t, stub.opKey, "op", claims)
			if _, err := stub.relyingParty(t).Client(t.Context(), stub.URL+"/op"); !errors.Is(err, ErrNotAnOpenIDProvider) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

// The master named by the location of its entity configuration: the entity identifier is what precedes the
// well-known path, and the built-in key is looked up by it.
func TestFedMaster_StatementURI_NamesTheMastersEntityIdentifier(t *testing.T) {
	cfg := &RelyingPartyConfig{FedMasterEntityStatementURI: "https://app-ref.federationmaster.de/.well-known/openid-federation"}
	entityID, err := cfg.fedMasterEntityID()
	if err != nil || entityID != "https://app-ref.federationmaster.de" {
		t.Fatalf("entity identifier %q, %v", entityID, err)
	}
	keys, err := cfg.resolveTrustAnchor()
	if err != nil || len(keys.Key("puk_fedmaster_sig")) != 1 {
		t.Fatalf("trust anchor %v, %v", keys, err)
	}
}

// Servers rule 17: a location that is not exactly an entity configuration's is refused at the start.
func TestFedMaster_StatementURI_ThatIsNotAnEntityConfigurationsIsRefused(t *testing.T) {
	for name, uri := range map[string]string{
		"plain http":        "http://master.example/.well-known/openid-federation",
		"a query":           "https://master.example/.well-known/openid-federation?x=1",
		"an empty query":    "https://master.example/.well-known/openid-federation?",
		"a fragment":        "https://master.example/.well-known/openid-federation#x",
		"user info":         "https://user@master.example/.well-known/openid-federation",
		"another path":      "https://master.example/.well-known/openid-configuration",
		"a trailing slash":  "https://master.example/.well-known/openid-federation/",
		"no host":           "https:///.well-known/openid-federation",
		"the path only":     "/.well-known/openid-federation",
		"a longer last seg": "https://master.example/.well-known/openid-federationx",
	} {
		cfg := &RelyingPartyConfig{FedMasterEntityStatementURI: uri}
		if _, err := cfg.fedMasterEntityID(); err == nil || !strings.Contains(err.Error(), "master_entity_statement_uri") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Exactly one way of naming the master: two could name two masters.
func TestFedMaster_StatementURI_IsExclusiveWithTheURL(t *testing.T) {
	both := &RelyingPartyConfig{FedMasterURL: "https://a.example", FedMasterEntityStatementURI: "https://a.example/.well-known/openid-federation"}
	if _, err := both.fedMasterEntityID(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both: %v", err)
	}
	if _, err := new(RelyingPartyConfig).fedMasterEntityID(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("none: %v", err)
	}
}

// The URI is a location, not a source of trust: an unlisted master needs master_jwk.
func TestFedMaster_StatementURI_OfAnUnlistedMasterNeedsItsKey(t *testing.T) {
	cfg := &RelyingPartyConfig{FedMasterEntityStatementURI: "https://unlisted.example/.well-known/openid-federation"}
	if _, err := cfg.resolveTrustAnchor(); err == nil || !strings.Contains(err.Error(), "master_jwk") {
		t.Errorf("err = %v", err)
	}
}

// A relying party built against the master named by its statement URI resolves it and names it in authority_hints.
func TestFedMaster_StatementURI_BuildsTheRelyingParty(t *testing.T) {
	stub := newFederationStub(t)
	cfg := testRelyingPartyConfig(t, stub)
	cfg.FedMasterURL = ""
	cfg.FedMasterEntityStatementURI = stub.URL + "/.well-known/openid-federation"
	rp, err := New(t.Context(), cfg, newTestKeys(t))
	if err != nil {
		t.Fatal(err)
	}
	if hints, _ := signedClaims(t, rp)["authority_hints"].([]any); len(hints) != 1 || hints[0] != stub.URL {
		t.Errorf("authority_hints = %v", hints)
	}
}

// gemSpec_IDP_FedMaster Tabelle 8: the list states its exp and holds an idp_entity array, or it is refused whole; an
// entry whose issuer is no entity identifier, or whose members are not as Tabelle 8 has them, is excluded and the
// others kept.
func TestFedMaster_TheIdPListIsReadStrictly(t *testing.T) {
	const exp = `"exp":4102444800,`
	for name, c := range map[string]struct{ payload, reason string }{
		"no exp":            {`{"idp_entity":[]}`, "has to state its exp"},
		"no idp_entity":     {`{` + exp + `"iss":"https://m.example"}`, "has no idp_entity"},
		"idp_entity null":   {`{` + exp + `"idp_entity":null}`, "no array"},
		"idp_entity object": {`{` + exp + `"idp_entity":{}}`, "no array"},
		"too many entries":  {`{` + exp + `"idp_entity":[` + strings.Repeat(`{},`, maxIdps) + `{}]}`, "more than"},
		"not UTF-8":         {"{" + exp + "\"idp_entity\":[{\"iss\":\"https://op.example\",\"organization_name\":\"\xff\"}]}", "not UTF-8"},
		"a member twice":    {`{` + exp + `"idp_entity":[],"idp_entity":[]}`, "named twice"},
	} {
		if _, _, err := parseIdpList([]byte(c.payload)); err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v", name, err)
		}
	}
	const good = `{"iss":"https://good.example"}`
	for name, entry := range map[string]string{
		"an entry not object": `"https://op.example"`,
		"no iss":              `{"organization_name":"x"}`,
		"iss not https":       `{"iss":"http://op.example"}`,
		"iss with a query":    `{"iss":"https://op.example?x"}`,
		"iss in another case": `{"ISS":"https://op.example"}`,
		"a name with a CR":    `{"iss":"https://op.example","organization_name":"a\rb"}`,
		"a name with RLO":     `{"iss":"https://op.example","organization_name":"a\u202eb"}`,
		"pkv not boolean":     `{"iss":"https://op.example","pkv":"no"}`,
		"user type a number":  `{"iss":"https://op.example","user_type_supported":1}`,
	} {
		idps, excluded, err := parseIdpList([]byte(`{` + exp + `"idp_entity":[` + entry + `,` + good + `]}`))
		if err != nil || excluded != 1 || len(idps) != 1 || idps[0].Issuer != "https://good.example" {
			t.Errorf("%s: %+v, %d excluded, %v", name, idps, excluded, err)
		}
	}
	idps, _, err := parseIdpList([]byte(`{` + exp + `"idp_entity":[{"iss":"https://op.example","organization_name":"Kasse","logo_uri":"https://op.example/l.png","pkv":true,"user_type_supported":["IP"]}]}`))
	if err != nil || len(idps) != 1 || idps[0].Issuer != "https://op.example" || !idps[0].IsPkv || idps[0].UserType != UserTypeIP {
		t.Fatalf("%+v, %v", idps, err)
	}
}

// gemSpec_IDP_FedMaster Tabelle 8: iss of the list is the master; a list signed with its key but naming another is
// refused.
func TestFedMaster_IdPList_OfAnotherIssuerIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	stub.idpList = signJWS(t, stub.masterKey, "master", map[string]any{
		"iss": "https://other.example", "exp": time.Now().Add(time.Hour).Unix(), "idp_entity": []any{},
	})
	if _, err := stub.federation(t).FetchIdpList(t.Context()); err == nil || !strings.Contains(err.Error(), "iss names another") {
		t.Fatalf("err = %v", err)
	}
}

func FuzzIdpList(f *testing.F) {
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"https://op.example","organization_name":"OP","logo_uri":"","pkv":false,"user_type_supported":"IP"}]}`))
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"https://op.example","user_type_supported":["IP","HP"]}]}`))
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"https://op.example/%2F..","organization_name":"\u202e"}]}`))
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"https://op.example\r\nX: y"}]}`))
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"javascript:alert(1)"}],"idp_entity":[]}`))
	f.Add([]byte(`{"exp":1,"idp_entity":[{"iss":"https://a@op.example"},{"iss":1e999}]}`))
	f.Fuzz(func(t *testing.T, payload []byte) {
		idps, _, err := parseIdpList(payload)
		if err != nil {
			if len(payload) >= 16 && strings.Contains(err.Error(), string(payload)) {
				t.Fatalf("the error holds the input: %v", err)
			}
			return
		}
		if len(idps) > maxIdps {
			t.Fatalf("%d entries", len(idps))
		}
		for _, idp := range idps {
			if checkEntityIdentifier(idp.Issuer) != nil {
				t.Fatalf("accepted issuer %q", idp.Issuer)
			}
			for _, text := range []string{idp.Issuer, idp.OrganizationName, idp.LogoURI, string(idp.UserType)} {
				if !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
					t.Fatalf("accepted text %q", text)
				}
			}
		}
	})
}

// An entry outside the grammar is excluded, not the list: the good issuer is admitted, the excluded one never, and the
// list stays kept. The operator learns how many entries were excluded, never what they held.
func TestFedMaster_IdPList_AnEntryOutsideTheGrammarIsExcluded(t *testing.T) {
	stub := newFederationStub(t)
	bad := stub.URL + "/bad"
	stub.idpList = signJWS(t, stub.masterKey, "master", map[string]any{
		"iss": stub.URL, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"idp_entity": []any{map[string]any{"iss": bad, "organization_name": "a\r\nb"}, map[string]any{"iss": stub.URL + "/op"}},
	})
	var logs bytes.Buffer
	rp := stub.relyingParty(t)
	rp.federation = stub.federationWith(t, WithDocuments(NewMemoryDocuments(16, nil)), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	fetches := stub.countFetches()
	if _, err := rp.Client(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatalf("the good issuer: %v", err)
	}
	if _, err := rp.Client(t.Context(), bad); !errors.Is(err, ErrIDPNotAdmitted) {
		t.Fatalf("the excluded issuer: %v", err)
	}
	if n := fetches.count("/idps"); n > 1 {
		t.Errorf("the list was fetched %d times for two logins", n)
	}
	if !strings.Contains(logs.String(), "excluded=1") || strings.Contains(logs.String(), "/bad") || strings.Count(logs.String(), "excluded=") != 1 {
		t.Errorf("logged:\n%s", logs.String())
	}
}

// Servers rule 2: an idp_iss outside the grammar of an entity identifier is refused before any request leaves, the
// IdP list's included.
func TestServerRule2_ARefusedIssuerMakesNoRequest(t *testing.T) {
	stub := newFederationStub(t)
	rp := stub.relyingParty(t)
	fetches := stub.countFetches()
	for _, issuer := range []string{
		stub.URL + "/op/../op", stub.URL + "/%6fp", stub.URL + "//op", stub.URL + "/op\r\n", "javascript:alert(1)",
		strings.Replace(stub.URL, "127.0.0.1", "127.0.0.1.", 1) + "/op",
	} {
		if _, err := rp.Client(t.Context(), issuer); !errors.Is(err, ErrIDPNotAdmitted) || !errors.Is(err, ErrEntityIdentifier) {
			t.Errorf("%q: %v", issuer, err)
		}
	}
	if n := fetches.total(); n != 0 {
		t.Fatalf("%d requests for refused issuers", n)
	}
}
