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

package pep_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/pep"
)

const zetaClaims = `{"sub":"1-234567890123","profession_oid":"1.2.276.0.76.4.50","common_name":"Arztpraxis Walter",` +
	`"organization_name":"Arztpraxis Walter","client_id":"c1","product_id":"p1","product_version":"1.0.0",` +
	`"platform":"linux","scope":"read"}`

func setClaims(raw string) pep.Enforcer {
	return pep.EnforcerFromFunc(func(ctx pep.Context, next pep.HandlerFunc) {
		ctx.SetClaims([]byte(raw))
		next(ctx)
	})
}

func denyAfterClaims(raw string) pep.Enforcer {
	return pep.EnforcerFromFunc(func(ctx pep.Context, _ pep.HandlerFunc) {
		ctx.SetClaims([]byte(raw))
		ctx.Deny(pep.ErrorAccessDeinied("denied"))
	})
}

var allow = pep.EnforcerFromFunc(func(ctx pep.Context, next pep.HandlerFunc) { next(ctx) })

// applied runs enforcer and returns the context its next got, nil when it denied.
func applied(t *testing.T, enforcer pep.Enforcer) pep.Context {
	t.Helper()
	var got pep.Context
	ctx := createPEP(t).NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://example.com/", http.NoBody))
	enforcer.Apply(ctx, func(c pep.Context) { got = c })
	return got
}

func decoded(t *testing.T, value string) map[string]any {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("not Base64-URL: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestA_26589_01_ClaimsSetInsideAllOfReachTheHandlerAfterThePolicy(t *testing.T) {
	allOf := &pep.EnforcerAllOf{TypeVal: pep.EnforcerTypeAllOf}
	allOf.Append(setClaims(zetaClaims))
	allOf.Append(&pep.EnforcerScope{TypeVal: pep.EnforcerTypeScope, Scope: "read"})
	ctx := applied(t, allOf)
	if ctx == nil {
		t.Fatal("denied")
	}
	if _, err := pep.ZETAUserInfo(ctx); err != nil {
		t.Fatalf("the handler after all_of sees no claims: %v", err)
	}
}

func TestA_26589_01_ClaimsSetInsideAnyOfReachTheHandlerAfterThePolicy(t *testing.T) {
	anyOf := &pep.EnforcerAnyOf{TypeVal: pep.EnforcerTypeAnyOf}
	anyOf.Append(setClaims(zetaClaims))
	ctx := applied(t, anyOf)
	if ctx == nil {
		t.Fatal("denied")
	}
	if _, err := pep.ZETAUserInfo(ctx); err != nil {
		t.Fatalf("the handler after any_of sees no claims: %v", err)
	}
}

func TestA_26589_01_ADeniedAnyOfBranchLeavesNoClaimsBehind(t *testing.T) {
	anyOf := &pep.EnforcerAnyOf{TypeVal: pep.EnforcerTypeAnyOf}
	anyOf.Append(denyAfterClaims(zetaClaims))
	anyOf.Append(allow)
	ctx := applied(t, anyOf)
	if ctx == nil {
		t.Fatal("denied")
	}
	if _, err := pep.ZETAUserInfo(ctx); err == nil {
		t.Fatal("the claims of the denied branch reached the handler")
	}
}

func TestA_26589_01_ADeniedAnyOfBranchKeepsTheClaimsSetBeforeIt(t *testing.T) {
	anyOf := &pep.EnforcerAnyOf{TypeVal: pep.EnforcerTypeAnyOf}
	anyOf.Append(denyAfterClaims(`{"sub":"other"}`))
	anyOf.Append(allow)
	allOf := &pep.EnforcerAllOf{TypeVal: pep.EnforcerTypeAllOf}
	allOf.Append(setClaims(zetaClaims))
	allOf.Append(anyOf)
	ctx := applied(t, allOf)
	if ctx == nil {
		t.Fatal("denied")
	}
	v, err := pep.ZETAUserInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded(t, v)["identifier"]; got != "1-234567890123" {
		t.Fatalf("identifier %v", got)
	}
}

func TestA_26589_01_UserInfoCarriesTheUserDataOfTheToken(t *testing.T) {
	v, err := pep.ZETAUserInfo(applied(t, setClaims(zetaClaims)))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"identifier": "1-234567890123", "professionOID": "1.2.276.0.76.4.50",
		"commonName": "Arztpraxis Walter", "organizationName": "Arztpraxis Walter",
	}
	got := decoded(t, v)
	if len(got) != len(want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s = %v, want %v", k, got[k], w)
		}
	}
}

func TestA_26589_01_UserInfoCarriesTheBirthdateOfTheToken(t *testing.T) {
	v, err := pep.ZETAUserInfo(applied(t, setClaims(`{"sub":"X1","profession_oid":"1.2.276.0.76.4.49","common_name":"Erika","birthdate":"1964-08-12"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded(t, v)["birthdate"]; got != "1964-08-12" {
		t.Fatalf("birthdate %v", got)
	}
}

func TestA_26589_01_AMalformedBirthdateIsLeftOut(t *testing.T) {
	for _, bad := range []string{"12.08.1964", "1964-02-30", "1964-8-12", "1964-08-12T00:00:00Z", ""} {
		v, err := pep.ZETAUserInfo(applied(t, setClaims(`{"sub":"X1","profession_oid":"1.2.276.0.76.4.49","common_name":"Erika","birthdate":"`+bad+`"}`)))
		if err != nil {
			t.Fatalf("%q: %v", bad, err)
		}
		if _, ok := decoded(t, v)["birthdate"]; ok {
			t.Errorf("%q carried", bad)
		}
	}
}

func TestA_26589_01_UserInfoOmitsAnAbsentOrganizationName(t *testing.T) {
	v, err := pep.ZETAUserInfo(applied(t, setClaims(`{"sub":"X1","profession_oid":"1.2.276.0.76.4.49","common_name":"Erika"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded(t, v)["organizationName"]; ok {
		t.Fatal("organizationName present")
	}
}

func TestA_26589_01_ATokenWithoutTheRequiredUserDataIsAnError(t *testing.T) {
	for _, raw := range []string{
		`{"profession_oid":"1.2.276.0.76.4.50","common_name":"A"}`,
		`{"sub":"X","common_name":"A"}`,
		`{"sub":"X","profession_oid":"1.2.276.0.76.4.50"}`,
		`{"sub":1,"profession_oid":"1.2.276.0.76.4.50","common_name":"A"}`,
	} {
		if _, err := pep.ZETAUserInfo(applied(t, setClaims(raw))); err == nil {
			t.Errorf("%s: no error", raw)
		}
	}
}

func TestA_26590_02_ClientDataCarriesTheClientDataOfTheToken(t *testing.T) {
	v, err := pep.ZETAClientData(applied(t, setClaims(zetaClaims)))
	if err != nil {
		t.Fatal(err)
	}
	got := decoded(t, v)
	want := map[string]any{"client_id": "c1", "product_id": "p1", "product_version": "1.0.0", "platform": "linux"}
	if len(got) != len(want) {
		t.Fatalf("members %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s = %v, want %v", k, got[k], w)
		}
	}
}

func TestA_26590_02_ClientDataNamesThePlatformOther(t *testing.T) {
	v, err := pep.ZETAClientData(applied(t, setClaims(`{"client_id":"c","product_id":"p","product_version":"1","platform":"other"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded(t, v)["platform"]; got != "other" {
		t.Fatalf("platform %v", got)
	}
}

func TestA_26590_02_ClientDataNamesOnlyAPlatformOfTheSchema(t *testing.T) {
	v, err := pep.ZETAClientData(applied(t, setClaims(`{"client_id":"c","product_id":"p","product_version":"1","platform":"amiga"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded(t, v)["platform"]; ok {
		t.Fatal("platform outside the schema's enum named")
	}
}

func TestA_26590_02_ATokenWithoutTheRequiredClientDataIsAnError(t *testing.T) {
	if _, err := pep.ZETAClientData(applied(t, setClaims(`{"client_id":"c","product_id":"p"}`))); err == nil {
		t.Fatal("no error")
	}
}

func TestA_25669_01_WithoutClaimsThereIsNoHeader(t *testing.T) {
	if _, err := pep.ZETAUserInfo(applied(t, allow)); err == nil {
		t.Fatal("user info without claims")
	}
}
