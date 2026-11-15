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

package oidftest_test

import (
	"crypto/tls"
	"encoding/json/v2"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/oidf/oidftest"
	"github.com/gematik/zero-lab/go/openid"
)

// The relying party of package oidf checks a login before it pushes it, so these tests send what it never would, to
// show that the IDP refuses it and does not merely accept whatever comes.

// The example's test of a host runs, since an example has no *testing.T to run it with.
func TestLogInFromTheExample(t *testing.T) {
	logIn(t)
}

// mutualTLS is the federation's client presenting certificate.
func mutualTLS(federation *oidftest.Federation, certificate tls.Certificate) *http.Client {
	client := *federation.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &certificate, nil
	}
	client.Transport = transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func pushedForm() url.Values {
	return url.Values{
		"client_id":             {"https://rp.example"},
		"redirect_uri":          {"https://rp.example/cb"},
		"response_type":         {"code"},
		"scope":                 {"openid urn:telematik:display_name"},
		"state":                 {"state"},
		"nonce":                 {"nonce"},
		"code_challenge":        {openid.S256Challenge(testVerifier)},
		"code_challenge_method": {"S256"},
	}
}

// post sends form and returns the status and the error code of the answer.
func post(t *testing.T, client *http.Client, endpoint string, form url.Values) (int, map[string]any) {
	t.Helper()
	response, err := client.PostForm(endpoint, form)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.UnmarshalRead(response.Body, &body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

// RFC 9126 section 2, RFC 8705 section 2.2, RFC 7636 section 4.3: the IDP holds a pushed request to the relying
// party's registration and says why it refuses one.
func TestRFC9126_2_APushedRequestOutsideTheRegistrationIsRefused(t *testing.T) {
	federation := oidftest.New(t)
	_, keys := newRelyingParty(t, federation)
	par := federation.IDP().Issuer() + "/par"
	authenticated := mutualTLS(federation, keys.Client)
	for _, c := range []struct {
		name   string
		client *http.Client
		change func(url.Values)
		code   string
		reason string
	}{
		{"without a client certificate", federation.Client(), nil, "invalid_client", "no client certificate"},
		{"with another client certificate", mutualTLS(federation, selfSigned(t)), nil, "invalid_client", "x5c"},
		{"of an unregistered client", authenticated, func(f url.Values) { f.Set("client_id", "https://other.example") }, "invalid_client", "no registered"},
		{"to another redirect_uri", authenticated, func(f url.Values) { f.Set("redirect_uri", "https://rp.example/cb/") }, "invalid_request", "redirect_uri"},
		{"for an unregistered scope", authenticated, func(f url.Values) { f.Set("scope", "openid urn:telematik:email") }, "invalid_scope", "did not register"},
		{"without openid", authenticated, func(f url.Values) { f.Set("scope", "urn:telematik:display_name") }, "invalid_scope", "openid"},
		{"with PKCE plain", authenticated, func(f url.Values) { f.Set("code_challenge_method", "plain") }, "invalid_request", "S256"},
		{"without a nonce", authenticated, func(f url.Values) { f.Del("nonce") }, "invalid_request", "nonce"},
		{"with state twice", authenticated, func(f url.Values) { f.Add("state", "again") }, "invalid_request", "more than once"},
	} {
		t.Run(c.name, func(t *testing.T) {
			form := pushedForm()
			if c.change != nil {
				c.change(form)
			}
			status, body := post(t, c.client, par, form)
			if status < 400 || body["error"] != c.code {
				t.Fatalf("status %d, body %v", status, body)
			}
			if !strings.Contains(federation.IDP().LastError(), c.reason) {
				t.Errorf("refused for %q", federation.IDP().LastError())
			}
		})
	}
}

// RFC 9126 section 2.2: a request_uri is taken once and within its expires_in.
func TestRFC9126_2_2_ARequestURIIsTakenOnceWithinItsLifetime(t *testing.T) {
	var now atomic.Pointer[time.Time]
	start := time.Now()
	now.Store(&start)
	federation := oidftest.New(t, oidftest.WithClock(func() time.Time { return *now.Load() }))
	_, keys := newRelyingParty(t, federation)
	client := mutualTLS(federation, keys.Client)
	push := func() string {
		status, body := post(t, client, federation.IDP().Issuer()+"/par", pushedForm())
		if status != http.StatusCreated {
			t.Fatalf("status %d, body %v", status, body)
		}
		return federation.IDP().Issuer() + "/auth?" + url.Values{"client_id": {"https://rp.example"}, "request_uri": {body["request_uri"].(string)}}.Encode()
	}

	authorization := push()
	if _, err := federation.Authorize(t.Context(), authorization); err != nil {
		t.Fatal(err)
	}
	if _, err := federation.Authorize(t.Context(), authorization); err == nil || !strings.Contains(federation.IDP().LastError(), "unknown or used") {
		t.Errorf("taken twice: %v, %q", err, federation.IDP().LastError())
	}

	authorization = push()
	later := start.Add(91 * time.Second)
	now.Store(&later)
	if _, err := federation.Authorize(t.Context(), authorization); err == nil || !strings.Contains(federation.IDP().LastError(), "expired") {
		t.Errorf("taken after its lifetime: %v, %q", err, federation.IDP().LastError())
	}
}

// RFC 6749 section 4.1.3, RFC 8705 section 2.2: the code is redeemed only by the client it was issued to, over its
// mutual TLS and with the redirect_uri of its request.
func TestRFC6749_4_1_3_TheTokenRequestIsHeldToTheCodesRequest(t *testing.T) {
	federation := oidftest.New(t)
	_, keys := newRelyingParty(t, federation)
	client := mutualTLS(federation, keys.Client)
	code := func() string {
		status, body := post(t, client, federation.IDP().Issuer()+"/par", pushedForm())
		if status != http.StatusCreated {
			t.Fatalf("status %d, body %v", status, body)
		}
		callback, err := federation.Authorize(t.Context(), federation.IDP().Issuer()+"/auth?"+
			url.Values{"client_id": {"https://rp.example"}, "request_uri": {body["request_uri"].(string)}}.Encode())
		if err != nil {
			t.Fatal(err)
		}
		return callback.Query().Get("code")
	}
	tokenForm := func(code string) url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"https://rp.example"},
			"redirect_uri": {"https://rp.example/cb"}, "code_verifier": {testVerifier},
		}
	}
	for _, c := range []struct {
		name   string
		client *http.Client
		change func(url.Values)
		code   string
		reason string
	}{
		{"without a client certificate", federation.Client(), nil, "invalid_client", "no client certificate"},
		{"with another redirect_uri", client, func(f url.Values) { f.Set("redirect_uri", "https://rp.example/other") }, "invalid_grant", "redirect_uri"},
		{"with another grant_type", client, func(f url.Values) { f.Set("grant_type", "client_credentials") }, "unsupported_grant_type", "grant_type"},
	} {
		t.Run(c.name, func(t *testing.T) {
			form := tokenForm(code())
			if c.change != nil {
				c.change(form)
			}
			status, body := post(t, c.client, federation.IDP().Issuer()+"/token", form)
			if status < 400 || body["error"] != c.code {
				t.Fatalf("status %d, body %v", status, body)
			}
			if !strings.Contains(federation.IDP().LastError(), c.reason) {
				t.Errorf("refused for %q", federation.IDP().LastError())
			}
		})
	}
	status, body := post(t, client, federation.IDP().Issuer()+"/token", tokenForm(code()))
	if status != http.StatusOK || body["token_type"] != "Bearer" || strings.Count(body["id_token"].(string), ".") != 4 {
		t.Fatalf("status %d, body %v", status, body)
	}
}
