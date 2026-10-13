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

package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSmoke_Metadata(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	if md.Issuer == "" {
		t.Fatal("metadata: empty issuer")
	}
	if md.TokenEndpoint == "" || md.JwksURI == "" || md.AuthorizationEndpoint == "" {
		t.Fatalf("metadata: missing core endpoints: %+v", md)
	}
}

func TestSmoke_JWKS(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	if set := getJWKS(t, md); set.Len() == 0 {
		t.Fatal("jwks: no keys")
	}
}

func TestSmoke_Nonce(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	resp := mustGet(t, httpClient(), md.NonceEndpoint)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nonce GET: status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("nonce GET: content-type %q, want text/plain", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) == "" {
		t.Fatal("nonce GET: empty body")
	}
}

func TestSmoke_OpenidProviders(t *testing.T) {
	md := getMetadata(t, baseURL(t))
	_ = getOpenidProviders(t, md) // 200 + JSON array (may be empty when no OP configured)
}

func TestSmoke_OIDFEntityStatement(t *testing.T) {
	base := baseURL(t)
	resp := mustGet(t, httpClient(), base+"/.well-known/openid-federation")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Skip("OIDF entity statement not configured")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entity statement: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(strings.Split(strings.TrimSpace(string(body)), ".")) != 3 {
		t.Fatalf("entity statement: not a JWT (got %d bytes)", len(body))
	}
}
