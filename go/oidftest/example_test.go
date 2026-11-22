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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/oidf"
	"github.com/gematik/zero-lab/go/oidftest"
	"github.com/gematik/zero-lab/go/openid"
)

// newRelyingParty builds a relying party of the federation as a host does, and has the master onboard it.
func newRelyingParty(t *testing.T, federation *oidftest.Federation) (*oidf.RelyingParty, oidf.Keys) {
	t.Helper()
	keys := oidf.Keys{SignKID: "sign", DecryptKID: "enc", ClientKID: "client"}
	keys.Sign = newKey(t)
	agreement, err := newKey(t).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	keys.Decrypt = agreement
	keys.Client = selfSigned(t)
	rp, err := oidf.New(t.Context(), &oidf.RelyingPartyConfig{
		Subject:      "https://rp.example",
		FedMasterURL: federation.MasterURL(),
		FedMasterJWK: &oidf.Jwk{Key: &federation.TrustAnchor().Keys[0]},
		RelyingParty: oidf.RelyingPartyMetadata{
			ClientName:          "rp",
			OrganizationName:    "Example",
			RedirectURIs:        []string{"https://rp.example/cb"},
			Keywords:            []string{"product_type:example", "product_type_version:0.0.0"},
			Contacts:            []string{"support@example.invalid"},
			TIFeaturesSupported: &oidf.TIFeatures{IDTokenVersionSupported: []string{"1.0.0"}},
		},
		FederationEntity: oidf.FederationEntity{Name: "rp", OrganizationName: "Example"},
		HTTPClient:       federation.Client(),
		Documents:        oidf.NewMemoryDocuments(16, nil),
	}, keys)
	if err != nil {
		t.Fatal(err)
	}
	federation.RegisterRelyingParty(rp.ClientID(), rp.SignEntityStatement)
	return rp, keys
}

// logIn is a test of a host: a login at the federation's IDP from the authorization request to the identity.
func logIn(t *testing.T) {
	federation := oidftest.New(t)
	rp, _ := newRelyingParty(t, federation)
	client, err := rp.Client(t.Context(), federation.IDP().Issuer())
	if err != nil {
		t.Fatal(err)
	}
	login := openid.Login{State: rand.Text(), Nonce: rand.Text(), Verifier: openid.GenerateVerifier()}
	authenticationURL, err := client.AuthenticationURL(t.Context(), login)
	if err != nil {
		t.Fatal(err)
	}
	// The browser's part: the IDP authenticates the user at once and redirects with the code.
	callback, err := federation.Authorize(t.Context(), authenticationURL)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := client.ExchangeIdentity(t.Context(), login, callback.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.Personal.DisplayName != oidftest.DefaultUser.DisplayName {
		t.Errorf("logged in as another")
	}
}

// Example shows a test of a host that logs a relying party in at the test federation; logIn takes the test's
// *testing.T, which an example has none of.
func Example() {
	_ = logIn
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// selfSigned is a client certificate for self_signed_tls_client_auth.
func selfSigned(t *testing.T) tls.Certificate {
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
