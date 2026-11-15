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

package oidf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/oidf/oidftest"
	"github.com/gematik/zero-lab/go/openid"
)

// These tests run a relying party built by oidf.New against the test federation: the master's documents, the IdP
// list, the IDP's statement and signed JWKS, PAR and the token request over mutual TLS, and the encrypted ID token.

const rpEntity = "https://rp.example"

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// clientCertificate is a self-signed certificate for self_signed_tls_client_auth.
func clientCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newKeys(t *testing.T) oidf.Keys {
	t.Helper()
	agreement, err := newKey(t).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return oidf.Keys{
		Sign: newKey(t), SignKID: "sign",
		Decrypt: agreement, DecryptKID: "enc",
		Client: clientCertificate(t), ClientKID: "client",
	}
}

// relyingParty builds a relying party of the federation with keys, the config changed first, without registering it.
func relyingParty(t *testing.T, federation *oidftest.Federation, keys oidf.Keys, change func(*oidf.RelyingPartyConfig)) *oidf.RelyingParty {
	t.Helper()
	cfg := &oidf.RelyingPartyConfig{
		Subject:      rpEntity,
		FedMasterURL: federation.MasterURL(),
		FedMasterJWK: &oidf.Jwk{Key: &federation.TrustAnchor().Keys[0]},
		RelyingParty: oidf.RelyingPartyMetadata{
			ClientName:          "rp",
			OrganizationName:    "Example",
			RedirectURIs:        []string{rpEntity + "/cb"},
			Keywords:            []string{"product_type:zero-lab", "product_type_version:0.0.0"},
			Contacts:            []string{"support@example.invalid"},
			TIFeaturesSupported: &oidf.TIFeatures{IDTokenVersionSupported: []string{"1.0.0", "2.0.0"}},
		},
		FederationEntity: oidf.FederationEntity{Name: "rp", OrganizationName: "Example"},
		HTTPClient:       federation.Client(),
		Documents:        oidf.NewMemoryDocuments(16, nil),
	}
	if change != nil {
		change(cfg)
	}
	rp, err := oidf.New(t.Context(), cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// registered is a relying party of a new federation, onboarded by the master, and a client of the federation's IDP.
func registered(t *testing.T) (*oidftest.Federation, *oidf.RelyingPartyClient) {
	t.Helper()
	federation := oidftest.New(t)
	rp := relyingParty(t, federation, newKeys(t), nil)
	federation.RegisterRelyingParty(rp.ClientID(), rp.SignEntityStatement)
	client, err := rp.Client(t.Context(), federation.IDP().Issuer())
	if err != nil {
		t.Fatal(err)
	}
	return federation, client
}

func newLogin() openid.Login {
	return openid.Login{State: rand.Text(), Nonce: rand.Text(), Verifier: openid.GenerateVerifier()}
}

// authorize pushes the login's request and follows the IDP's authorization endpoint to the code it redirects with.
func authorize(t *testing.T, federation *oidftest.Federation, client *oidf.RelyingPartyClient, login openid.Login) string {
	t.Helper()
	authenticationURL, err := client.AuthenticationURL(t.Context(), login)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := federation.Authorize(t.Context(), authenticationURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := redirect.Scheme + "://" + redirect.Host + redirect.Path; got != rpEntity+"/cb" {
		t.Fatalf("redirected to %s", got)
	}
	if redirect.Query().Get("state") != login.State {
		t.Fatal("the redirect carries another state")
	}
	return redirect.Query().Get("code")
}

// login logs in at the federation's IDP from the start to the identity.
func login(t *testing.T, federation *oidftest.Federation, client *oidf.RelyingPartyClient) (*oidf.Identity, *openid.TokenResponse, error) {
	t.Helper()
	login := newLogin()
	code := authorize(t, federation, client, login)
	return client.ExchangeIdentity(t.Context(), login, code)
}

// providerError is the IDP's refusal as the relying party returns it.
func providerError(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *oidf.Error
	if !errors.As(err, &refusal) || refusal.ErrorCode != code {
		t.Fatalf("err = %v, want the IDP's %s", err, code)
	}
}

// gemSpec_IDP_FD A_23195: the ID token is decrypted with the relying party's own key before it is used, and verified
// with the IDP's signed JWKS (A_23049). The whole login runs: PAR, authorization, token request, identity.
func TestA_23195_TheNestedIDTokenIsDecryptedAndVerified(t *testing.T) {
	federation, client := registered(t)
	identity, response, err := login(t, federation, client)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(response.IDTokenRaw, ".") != 2 {
		t.Errorf("IDTokenRaw is not the inner JWS")
	}
	user := oidftest.DefaultUser
	if identity.Issuer != federation.IDP().Issuer() || identity.Personal.Subject == "" ||
		identity.Personal.DisplayName != user.DisplayName || identity.Personal.ID != user.ID ||
		identity.Profession != user.Profession || identity.Organization != user.Organization {
		t.Errorf("identity %s: sub %q display_name %q id %q", identity, identity.Personal.Subject, identity.Personal.DisplayName, identity.Personal.ID)
	}
	if identity.ACR != oidf.LoAHigh || !slices.Equal(identity.AMR, []string{oidftest.DefaultAMR}) || identity.IDTokenVersion != "1.0.0" {
		t.Errorf("acr %s amr %v version %s", identity.ACR, identity.AMR, identity.IDTokenVersion)
	}
	if !slices.Equal(identity.Scopes, []string{"openid", "urn:telematik:display_name", "urn:telematik:versicherter"}) {
		t.Errorf("scopes %v", identity.Scopes)
	}
	// Scope urn:telematik:geburtsdatum was not asked for (gemSpec_IDP_Sek Tabelle 6).
	if identity.Personal.Birthdate != "" {
		t.Error("birthdate without its scope")
	}
}

// gemSpec_IDP_FD A_23049, OIDC Core 3.1.3.7 step 11: a token issued for another login must not be accepted for this one.
func TestA_23049_AnIDTokenOfAnotherLoginIsRefused(t *testing.T) {
	federation, client := registered(t)
	first := newLogin()
	code := authorize(t, federation, client, first)
	another := first
	another.Nonce = rand.Text()
	if _, _, err := client.ExchangeIdentity(t.Context(), another, code); !errors.Is(err, openid.ErrNonceMismatch) {
		t.Fatalf("err = %v", err)
	}
}

// gemSpec_IDP_FD A_23049, OIDC Core 3.1.3.7 step 9: an ID token past its exp is refused.
func TestA_23049_AnExpiredIDTokenIsRefused(t *testing.T) {
	federation, client := registered(t)
	federation.IDP().ExpireIDToken()
	if _, _, err := login(t, federation, client); !errors.Is(err, openid.ErrTokenExpired) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := login(t, federation, client); err != nil {
		t.Fatalf("the next login: %v", err)
	}
}

// gemSpec_IDP_FD A_28484: an acr lower than the login asked for, high by default, is refused.
func TestA_28484_AnIDPIssuingALowerACRIsRefused(t *testing.T) {
	federation, client := registered(t)
	federation.IDP().IssueACR(oidf.LoASubstantial)
	if _, _, err := login(t, federation, client); !errors.Is(err, oidf.ErrACR) {
		t.Fatalf("err = %v", err)
	}
}

// gemSpec_IDP_FedMaster Tabelle 8, servers.md rule 2: an IDP off the master's IdP list is refused before anything is
// fetched at or about it.
func TestFedMaster_IdPList_AnUnlistedIDPIsRefusedBeforeAnyFetch(t *testing.T) {
	federation := oidftest.New(t)
	federation.IDP().Unlist()
	rp := relyingParty(t, federation, newKeys(t), nil)
	if _, err := rp.Client(t.Context(), federation.IDP().Issuer()); !errors.Is(err, oidf.ErrIDPNotAdmitted) {
		t.Fatalf("err = %v", err)
	}
	for _, path := range []string{"/fetch", "/idp/.well-known/openid-federation", "/idp/jwks"} {
		if n := federation.Requests(path); n != 0 {
			t.Errorf("%s fetched %d times", path, n)
		}
	}
}

// gemSpec_IDP_FD A_22861: an ID token signed with a key the kept JWKS does not name refetches the signed JWKS once,
// and the rotated key verifies.
func TestA_22861_ARotatedKeyIsFetchedOnce(t *testing.T) {
	federation, client := registered(t)
	if _, _, err := login(t, federation, client); err != nil {
		t.Fatal(err)
	}
	federation.IDP().RotateKey()
	if _, _, err := login(t, federation, client); err != nil {
		t.Fatal(err)
	}
	if n := federation.Requests("/idp/jwks"); n != 2 {
		t.Fatalf("the signed JWKS fetched %d times, want 2", n)
	}
	if _, _, err := login(t, federation, client); err != nil {
		t.Fatal(err)
	}
	if n := federation.Requests("/idp/jwks"); n != 2 {
		t.Fatalf("the signed JWKS fetched %d times after the refetch, want 2", n)
	}
}

// RFC 8705 section 2.2, gemSpec_IDP_FD A_23183: the IDP takes only the client certificate the relying party's statement
// publishes as x5c.
func TestRFC8705_2_2_AClientCertificateOtherThanTheStatementsIsRefusedAtPAR(t *testing.T) {
	federation := oidftest.New(t)
	rp := relyingParty(t, federation, newKeys(t), nil)
	// The statement the master onboards is one of the same entity with another client certificate.
	published := relyingParty(t, federation, newKeys(t), nil)
	federation.RegisterRelyingParty(published.ClientID(), published.SignEntityStatement)
	client, err := rp.Client(t.Context(), federation.IDP().Issuer())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AuthenticationURL(t.Context(), newLogin())
	providerError(t, err, "invalid_client")
	if !strings.Contains(federation.IDP().LastError(), "x5c") {
		t.Errorf("refused for %q", federation.IDP().LastError())
	}
}

// RFC 6749 section 4.1.2: an authorization code is redeemed once.
func TestRFC6749_4_1_2_ACodeIsRedeemedOnce(t *testing.T) {
	federation, client := registered(t)
	login := newLogin()
	code := authorize(t, federation, client, login)
	if _, _, err := client.ExchangeIdentity(t.Context(), login, code); err != nil {
		t.Fatal(err)
	}
	_, _, err := client.ExchangeIdentity(t.Context(), login, code)
	providerError(t, err, "invalid_grant")
	if !strings.Contains(federation.IDP().LastError(), "code is unknown or used") {
		t.Errorf("refused for %q", federation.IDP().LastError())
	}
}

// RFC 7636 section 4.6: the token request has to carry the verifier of the challenge pushed.
func TestRFC7636_4_6_AVerifierOtherThanTheChallengesIsRefused(t *testing.T) {
	federation, client := registered(t)
	login := newLogin()
	code := authorize(t, federation, client, login)
	login.Verifier = openid.GenerateVerifier()
	_, _, err := client.ExchangeIdentity(t.Context(), login, code)
	providerError(t, err, "invalid_grant")
	if !strings.Contains(federation.IDP().LastError(), "code_verifier") {
		t.Errorf("refused for %q", federation.IDP().LastError())
	}
}

// gemSpec_IDP_Sek A_27713-01, gemSpec_IDP_FD A_23207: the version the JWE header names is the identity's, when both
// sides list it.
func TestA_27713_01_TheVersionOfTheHeaderIsTheIdentitys(t *testing.T) {
	federation, client := registered(t)
	federation.IDP().IssueVersion("2.0.0")
	identity, _, err := login(t, federation, client)
	if err != nil {
		t.Fatal(err)
	}
	if identity.IDTokenVersion != "2.0.0" {
		t.Errorf("version %s", identity.IDTokenVersion)
	}
}

// OpenID Federation 1.1 section 5.1.3: an admitted entity whose statement describes no OpenID provider is refused.
func TestOIDF_AnAdmittedEntityWithoutOpenIDProviderMetadataIsRefused(t *testing.T) {
	federation := oidftest.New(t)
	federation.IDP().NotAnOP()
	rp := relyingParty(t, federation, newKeys(t), nil)
	if _, err := rp.Client(t.Context(), federation.IDP().Issuer()); !errors.Is(err, oidf.ErrNotAnOpenIDProvider) {
		t.Fatalf("err = %v", err)
	}
}

// gemSpec_IDP_Sek A_22989-02 Tabelle 6: the identity carries the claims of the scopes asked for, of the person who
// logged in.
func TestIDPSek_TheIdentityCarriesTheClaimsOfTheScopesAskedFor(t *testing.T) {
	federation := oidftest.New(t)
	scopes := []string{"openid", "urn:telematik:given_name", "urn:telematik:family_name", "urn:telematik:geburtsdatum"}
	rp := relyingParty(t, federation, newKeys(t), func(cfg *oidf.RelyingPartyConfig) {
		cfg.RelyingParty.Scope = strings.Join(scopes, " ")
		cfg.Scopes = scopes
	})
	federation.RegisterRelyingParty(rp.ClientID(), rp.SignEntityStatement)
	client, err := rp.Client(t.Context(), federation.IDP().Issuer())
	if err != nil {
		t.Fatal(err)
	}
	user := oidftest.User{ID: "A123456789", GivenName: "Max", FamilyName: "Muster", Birthdate: "1970-07-01", Subject: "pairwise-1"}
	federation.IDP().SetUser(user)
	identity, _, err := login(t, federation, client)
	if err != nil {
		t.Fatal(err)
	}
	want := oidf.Personal{Subject: user.Subject, GivenName: user.GivenName, FamilyName: user.FamilyName, Birthdate: user.Birthdate}
	if identity.Personal != want || identity.Profession != "" {
		p := identity.Personal
		t.Errorf("sub %q id %q given %q family %q birthdate %q display %q, profession %q", p.Subject, p.ID, p.GivenName, p.FamilyName, p.Birthdate, p.DisplayName, identity.Profession)
	}
}
