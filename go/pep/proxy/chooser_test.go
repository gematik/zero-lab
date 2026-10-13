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
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestSortProviders(t *testing.T) {
	providers := []Provider{
		{Issuer: "https://oidf-z", Name: "Zeta Klinik", Type: "oidf"},
		{Issuer: "https://oidc", Name: "Corporate SSO", Type: "oidc"},
		{Issuer: "https://oidf-a", Name: "alpha Praxis", Type: "oidf"},
		{Issuer: "https://gemidp", Name: "gematik IDP", Type: "gemidp"},
		{Issuer: "https://oidf-m", Name: "Mittel GmbH", Type: "oidf"},
	}
	sortProviders(providers)

	got := make([]string, len(providers))
	for i, p := range providers {
		got[i] = p.Name
	}
	want := []string{
		"Corporate SSO", // oidc — stays up, configured order
		"gematik IDP",   // gemidp — stays up, configured order
		"alpha Praxis",  // OIDF sorted by label (case-insensitive)
		"Mittel GmbH",
		"Zeta Klinik",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestSignInChooserRender(t *testing.T) {
	r, err := newRenderer("")
	if err != nil {
		t.Fatal(err)
	}
	var many []Provider
	for i := range 8 { // > 6 → search shows
		many = append(many, Provider{Issuer: "https://idp" + strconv.Itoa(i), Name: "IdP " + strconv.Itoa(i), Type: "oidf"})
	}
	rec := httptest.NewRecorder()
	r.render(rec, 200, "sign_in.html", signInData{Providers: many, ReturnTo: "/"})
	html := rec.Body.String()
	for _, want := range []string{
		`id="provider-search"`, `data-issuer="https://idp0"`, `data-name="IdP 0"`,
		"pep:last-provider", "function fuzzy", "last-used",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered chooser missing %q", want)
		}
	}

	// Search is hidden at 5 providers, shown only when there are more than 5.
	rec2 := httptest.NewRecorder()
	r.render(rec2, 200, "sign_in.html", signInData{Providers: many[:5], ReturnTo: "/"})
	if strings.Contains(rec2.Body.String(), `id="provider-search"`) {
		t.Error("search input shown for 5 providers (should appear only above 5)")
	}
}
