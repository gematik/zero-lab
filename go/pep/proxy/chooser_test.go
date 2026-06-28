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
	for i := 0; i < 8; i++ { // > 6 → search shows
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

	// Search is hidden when there are only a couple of providers.
	rec2 := httptest.NewRecorder()
	r.render(rec2, 200, "sign_in.html", signInData{Providers: many[:2], ReturnTo: "/"})
	if strings.Contains(rec2.Body.String(), `id="provider-search"`) {
		t.Error("search input shown for 2 providers (should be hidden until > 6)")
	}
}
