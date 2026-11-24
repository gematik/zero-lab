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

package zaddy

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/pep"
)

const tokenClaims = `{"sub":"1-234567890123","profession_oid":"1.2.276.0.76.4.50","common_name":"Arztpraxis Walter",` +
	`"client_id":"c1","product_id":"p1","product_version":"1.0.0"}`

// withClaims is a policy that lets every request through as a verified token with these claims would be.
func withClaims(t *testing.T, raw string, userInfo, clientData bool) EnforcePolicyMiddleware {
	t.Helper()
	built, err := pep.NewBuilder().Resource("https://rs.example").WithJWKSet(&jose.JSONWebKeySet{}).
		WithDPoPReplays(dpop.NewMemoryReplays(16, nil)).Build()
	if err != nil {
		t.Fatal(err)
	}
	allOf := &pep.EnforcerAllOf{TypeVal: pep.EnforcerTypeAllOf}
	allOf.Append(pep.EnforcerFromFunc(func(ctx pep.Context, next pep.HandlerFunc) {
		if raw != "" {
			ctx.SetClaims([]byte(raw))
		}
		next(ctx)
	}))
	return EnforcePolicyMiddleware{
		Enforcer:       &pep.EnforcerHolder{Enforcer: allOf},
		ZETAUserInfo:   userInfo,
		ZETAClientData: clientData,
		logger:         slog.New(slog.DiscardHandler),
		app:            &App{pep: built},
	}
}

type headerRecorder struct{ got *http.Header }

func (h headerRecorder) ServeHTTP(_ http.ResponseWriter, r *http.Request) error {
	*h.got = r.Header.Clone()
	return nil
}

// forwarded sends a request carrying client-made ZETA headers, a token and a proof through m and returns the
// response and the headers the upstream got, nil when it got none.
func forwarded(t *testing.T, m EnforcePolicyMiddleware) (*httptest.ResponseRecorder, http.Header) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://rs.example/api", http.NoBody)
	forged := base64.URLEncoding.EncodeToString([]byte(`{"identifier":"forged"}`))
	for _, name := range []string{"zeta-user-info", "ZETA-Client-Data", "zeta-popp-token-content"} {
		r.Header.Set(name, forged)
	}
	r.Header.Set("Authorization", "DPoP token")
	r.Header.Set("DPoP", "proof")
	w := httptest.NewRecorder()
	var got http.Header
	if err := m.ServeHTTP(w, r, headerRecorder{&got}); err != nil {
		t.Fatal(err)
	}
	return w, got
}

func TestA_25669_01_ZETAHeadersTheClientSentNeverReachTheUpstream(t *testing.T) {
	for _, on := range []bool{false, true} {
		_, got := forwarded(t, withClaims(t, tokenClaims, on, on))
		for _, name := range pep.ZETAHeaderNames() {
			for _, v := range got.Values(name) {
				if strings.Contains(decodedHeader(t, v), "forged") {
					t.Errorf("directives %v: the client's %s reached the upstream", on, name)
				}
			}
		}
		if !on && (got.Get(pep.HeaderZETAUserInfo) != "" || got.Get(pep.HeaderZETAClientData) != "") {
			t.Errorf("a ZETA header without its directive")
		}
	}
}

func TestA_26589_01_TheUpstreamGetsTheUserInfoOfTheToken(t *testing.T) {
	_, got := forwarded(t, withClaims(t, tokenClaims, true, false))
	if v := decodedHeader(t, got.Get(pep.HeaderZETAUserInfo)); !strings.Contains(v, `"identifier":"1-234567890123"`) {
		t.Fatalf("zeta-user-info %s", v)
	}
	if got.Get(pep.HeaderZETAClientData) != "" {
		t.Fatal("zeta-client-data although the endpoint did not ask for it (A_26492-02)")
	}
}

func TestA_26590_02_TheUpstreamGetsTheClientDataOfTheTokenWhenTheEndpointAsks(t *testing.T) {
	_, got := forwarded(t, withClaims(t, tokenClaims, false, true))
	if v := decodedHeader(t, got.Get(pep.HeaderZETAClientData)); !strings.Contains(v, `"client_id":"c1"`) {
		t.Fatalf("zeta-client-data %s", v)
	}
}

func TestA_26589_01_ARequestWhoseTokenLacksTheUserDataIsRefused(t *testing.T) {
	for _, raw := range []string{"", `{"sub":"1-234567890123"}`} {
		w, got := forwarded(t, withClaims(t, raw, true, false))
		if got != nil {
			t.Fatalf("claims %q: forwarded", raw)
		}
		if w.Code != http.StatusForbidden {
			t.Fatalf("claims %q: status %d", raw, w.Code)
		}
	}
}

func TestA_25669_01_AuthorizationAndDPoPArePassedOn(t *testing.T) {
	_, got := forwarded(t, withClaims(t, tokenClaims, true, true))
	if got.Get("Authorization") != "DPoP token" || got.Get("DPoP") != "proof" {
		t.Fatalf("Authorization %q, DPoP %q", got.Get("Authorization"), got.Get("DPoP"))
	}
}

func TestA_26492_02_ZETAHeadersAreSubdirectivesOfEnforcePolicy(t *testing.T) {
	parse := func(block string) (EnforcePolicyMiddleware, error) {
		h, err := parseCaddyfileEnforcePolicy(httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(block)})
		if err != nil {
			return EnforcePolicyMiddleware{}, err
		}
		return h.(EnforcePolicyMiddleware), nil
	}
	m, err := parse("enforce_policy {\n authorization_dpop\n zeta_user_info\n zeta_client_data\n}")
	if err != nil {
		t.Fatal(err)
	}
	if !m.ZETAUserInfo || !m.ZETAClientData {
		t.Fatalf("user info %v, client data %v", m.ZETAUserInfo, m.ZETAClientData)
	}
	if m, err = parse("enforce_policy {\n authorization_dpop\n}"); err != nil || m.ZETAUserInfo || m.ZETAClientData {
		t.Fatalf("defaults: %v %v %v", m.ZETAUserInfo, m.ZETAClientData, err)
	}
	for _, block := range []string{
		"enforce_policy {\n zeta_user_info on\n}",
		"enforce_policy {\n any_of {\n  zeta_client_data\n }\n}",
	} {
		if _, err := parse(block); err == nil {
			t.Errorf("%q accepted", block)
		}
	}
}

func decodedHeader(t *testing.T, v string) string {
	t.Helper()
	raw, err := base64.URLEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("%q is not Base64-URL: %v", v, err)
	}
	return string(raw)
}
