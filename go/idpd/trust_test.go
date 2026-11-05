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

package idpd

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/tipki"
)

// A brainpool certificate and its key, which the fake IDP signs with: no CA here vouches for it, which is
// the fake trust's business. The real chain is tested on BundleTrust.
const (
	//nolint:gosec // the test identity idpd_test.go carries too; a TEST-ONLY key of a certificate no one trusts
	idpKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHgCAQEEID0gGM/y+gETNO9kFWY6vELk9rjq2H/tuZogskG/rpB8oAsGCSskAwMC
CAEBB6FEA0IABGc0iasne1f/tcuTSw4CiRfxZ3LvLsQDuMmbqTO5CuOsXND+n8fV
Q3zyzOv7imMbR7nqdiEFGAHtGNznbsLrU80=
-----END EC PRIVATE KEY-----`
	idpCertPEM = `-----BEGIN CERTIFICATE-----
MIIDeDCCAx6gAwIBAgIHArLLcBI3KDAKBggqhkjOPQQDAjCBmjELMAkGA1UEBhMC
REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsMP0lu
c3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1hdGlr
aW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0E1MSBURVNULU9OTFkw
HhcNMjMxMTA5MjMwMDAwWhcNMjgxMTA5MjI1OTU5WjCBhDELMAkGA1UEBhMCREUx
HDAaBgNVBAoMEzEwMjMxMDgwMSBOT1QtVkFMSUQxFTATBgNVBAQMDFJvc2Vuc3Ry
YXVjaDEOMAwGA1UEKgwFQmVybmQxMDAuBgNVBAMMJ0FyenRwcmF4aXMgQmVybmQg
Um9zZW5zdHJhdWNoIFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNC
AARnNImrJ3tX/7XLk0sOAokX8Wdy7y7EA7jJm6kzuQrjrFzQ/p/H1UN88szr+4pj
G0e56nYhBRgB7Rjc527C61PNo4IBYDCCAVwwLAYDVR0fBCUwIzAhoB+gHYYbaHR0
cDovL2VoY2EuZ2VtYXRpay5kZS9jcmwvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUshKrzlr5DNSiNzsEXWLuScZAN2wwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBQGmOkCVf/Jn1yjZQ7xXeIg9YT7kzA7Bggr
BgEFBQcBAQQvMC0wKwYIKwYBBQUHMAGGH2h0dHA6Ly9laGNhLmdlbWF0aWsuZGUv
ZWNjLW9jc3AwWgYFKyQIAwMEUTBPME0wSzBJMEcwFgwUQmV0cmllYnNzdMOkdHRl
IEFyenQwCQYHKoIUAEwEMhMiMS0yLUFSWlRQUkFYSVMtQmVybmRSb3NlbnN0cmF1
Y2gwMTAgBgNVHSAEGTAXMAoGCCqCFABMBIEjMAkGByqCFABMBE0wCgYIKoZIzj0E
AwIDSAAwRQIgWlSdCIw6Z6alM+dGnA4vfkxDoViIqJMw/PH4U0VUmNsCIQCcX9UW
JnSDBKGp4nZTcuozRPsJK47cBkil0x6Zrkoxkg==
-----END CERTIFICATE-----`
)

// recording notes what it was asked and refuses what it is told to.
type recording struct {
	asked   []IDPCertificate
	refuse  map[IDPCertificate]bool
	subject []*x509.Certificate
}

func (r *recording) Check(_ context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	r.asked = append(r.asked, which)
	r.subject = certs
	if r.refuse[which] {
		return errors.New("refused")
	}
	return nil
}

type fakeIDP struct {
	*httptest.Server
	key       *ecdsa.PrivateKey
	cert      *x509.Certificate
	discovery func(base string) []byte
	sigJWK    func() map[string]any
	encJWK    func() map[string]any
	// token and authorization answer at the token and authorization endpoints the discovery document names.
	token         http.HandlerFunc
	authorization http.HandlerFunc
}

func jwkOf(t *testing.T, key *ecdsa.PublicKey, use string) map[string]any {
	t.Helper()
	data, err := json.Marshal(&josebp.JSONWebKey{Key: key, Use: use})
	if err != nil {
		t.Fatal(err)
	}
	jwk := make(map[string]any)
	if err := json.Unmarshal(data, &jwk); err != nil {
		t.Fatal(err)
	}
	return jwk
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := brainpool.ParsePrivateKeyPEM([]byte(idpKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := brainpool.ParseCertificatePEM([]byte(idpCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{key: key, cert: cert}
	idp.discovery = func(base string) []byte { return idp.signDiscovery(t, base, idp.key) }
	idp.sigJWK = func() map[string]any {
		jwk := jwkOf(t, &idp.key.PublicKey, "sig")
		jwk["x5c"] = []string{base64.StdEncoding.EncodeToString(idp.cert.Raw)}
		return jwk
	}
	idp.encJWK = func() map[string]any { return jwkOf(t, &idp.key.PublicKey, "enc") }
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(idp.discovery(idp.URL))
	})
	mux.HandleFunc("/certs/puk_idp_sig", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(idp.sigJWK())
	})
	mux.HandleFunc("/certs/puk_idp_enc", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(idp.encJWK())
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) { idp.token(w, r) })
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) { idp.authorization(w, r) })
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)
	return idp
}

func (idp *fakeIDP) signDiscovery(t *testing.T, base string, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	token, err := josebp.NewJWTBuilder().
		Header("alg", josebp.AlgorithmNameBP256R1).
		Header("kid", string(DiscoverySigner)).
		Header("x5c", []string{base64.StdEncoding.EncodeToString(idp.cert.Raw)}).
		Claim("issuer", base).
		Claim("authorization_endpoint", base+"/auth").
		Claim("token_endpoint", base+"/token").
		Claim("uri_puk_idp_sig", base+"/certs/puk_idp_sig").
		Claim("uri_puk_idp_enc", base+"/certs/puk_idp_enc").
		Sign(sha256.New(), brainpool.SignFuncPrivateKey(signer))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (idp *fakeIDP) config(trust CertificateTrust) ClientConfig {
	return ClientConfig{
		Environment: EnvironmentReference, BaseURL: idp.URL, ClientID: "client", RedirectURI: "https://rp/cb",
		Scopes: []string{"openid"}, Trust: trust, HTTPClient: idp.Client(),
	}
}

// The signature says who wrote the document, not that it describes the IDP asked for.
func TestASignedDiscoveryDocumentOfAnotherIssuerIsRefused(t *testing.T) {
	idp := newFakeIDP(t)
	idp.discovery = func(string) []byte { return idp.signDiscovery(t, "https://idp.other.example", idp.key) }
	_, err := NewClientFromConfig(idp.config(&recording{}))
	if err == nil || !strings.Contains(err.Error(), "names the issuer") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV001TheDiscoverySignerIsCheckedBeforeItsKeyIsUsed(t *testing.T) {
	idp := newFakeIDP(t)
	trust := &recording{}
	client, err := NewClientFromConfig(idp.config(trust))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(trust.asked, []IDPCertificate{DiscoverySigner}) || !trust.subject[0].Equal(idp.cert) {
		t.Errorf("asked %v", trust.asked)
	}
	if client.Issuer() != idp.URL {
		t.Errorf("issuer %q", client.Issuer())
	}
}

func TestIDPV001ARefusedSignerIsAHardError(t *testing.T) {
	idp := newFakeIDP(t)
	trust := &recording{refuse: map[IDPCertificate]bool{DiscoverySigner: true}}
	if _, err := NewClientFromConfig(idp.config(trust)); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v", err)
	}
	if _, err := NewAuthenticator(AuthenticatorConfig{IDP: NewIDP(EnvironmentReference, idp.URL), Trust: trust, HTTPClient: idp.Client()}); err == nil {
		t.Error("an authenticator went on")
	}
}

func TestIDPV001ATrustedCertificateDoesNotExcuseABadSignature(t *testing.T) {
	idp := newFakeIDP(t)
	other, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp.discovery = func(base string) []byte { return idp.signDiscovery(t, base, other) }
	_, err = NewClientFromConfig(idp.config(&recording{}))
	if err == nil || strings.Contains(err.Error(), "missing alg") {
		t.Errorf("a discovery document another key signed: %v", err)
	}
}

func TestIDPV002TheTokenSignerIsCheckedOnEveryFetch(t *testing.T) {
	idp := newFakeIDP(t)
	trust := &recording{}
	uri := idp.URL + "/certs/puk_idp_sig"
	for range 2 {
		if _, err := fetchSigningKey(t.Context(), uri, idp.Client(), trust); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(trust.asked, []IDPCertificate{TokenSigner, TokenSigner}) {
		t.Errorf("asked %v", trust.asked)
	}
	trust.refuse = map[IDPCertificate]bool{TokenSigner: true}
	if _, err := fetchSigningKey(t.Context(), uri, idp.Client(), trust); err == nil {
		t.Error("a refused signer's key was returned")
	}
}

func TestIDPV002AKeyWithoutItsCertificateIsRefused(t *testing.T) {
	idp := newFakeIDP(t)
	trust := &recording{}
	uri := idp.URL + "/certs/puk_idp_sig"
	idp.sigJWK = func() map[string]any { return jwkOf(t, &idp.key.PublicKey, "sig") }
	if _, err := fetchSigningKey(t.Context(), uri, idp.Client(), trust); err == nil || !strings.Contains(err.Error(), "no x5c") {
		t.Errorf("no x5c: %v", err)
	}
	other, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp.sigJWK = func() map[string]any {
		jwk := jwkOf(t, &other.PublicKey, "sig")
		jwk["x5c"] = []string{base64.StdEncoding.EncodeToString(idp.cert.Raw)}
		return jwk
	}
	if _, err := fetchSigningKey(t.Context(), uri, idp.Client(), trust); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("another key: %v", err)
	}
	if len(trust.asked) != 0 {
		t.Errorf("trust was asked %v about a key the certificate does not carry", trust.asked)
	}
}

func TestIDPV003ThereIsNoClientWithoutTrust(t *testing.T) {
	idp := newFakeIDP(t)
	if _, err := NewClientFromConfig(idp.config(nil)); err == nil {
		t.Error("a client without trust")
	}
	if _, err := NewAuthenticator(AuthenticatorConfig{IDP: NewIDP(EnvironmentReference, idp.URL), HTTPClient: idp.Client()}); err == nil {
		t.Error("an authenticator without trust")
	}
}

func TestIDPV004TheEncryptionKeyMustBeWhatItCanBe(t *testing.T) {
	idp := newFakeIDP(t)
	uri := idp.URL + "/certs/puk_idp_enc"
	if _, err := fetchEncryptionKey(t.Context(), uri, idp.Client()); err != nil {
		t.Fatal(err)
	}
	idp.encJWK = func() map[string]any { return jwkOf(t, &idp.key.PublicKey, "sig") }
	if _, err := fetchEncryptionKey(t.Context(), uri, idp.Client()); err == nil {
		t.Error("a key for signing")
	}
}

// captured is when spec/tsl-detached/testdata was fetched; testdata/ holds the reference IDP's certificates.
var captured = time.Date(2026, 11, 1, 16, 47, 42, 0, time.UTC)

const refList = "../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref"

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeBundle(t *testing.T, path string, fetchedAt time.Time) {
	t.Helper()
	anchor := sha256.Sum256(tipki.AnchorNonProd)
	b64 := func(path string) string { return base64.StdEncoding.EncodeToString(readFile(t, path)) }
	meta := map[string]any{"fetched_at": fetchedAt.Unix(), "source": "file"}
	data, err := json.Marshal(map[string]any{
		"format_version": 2, "label": "test", "anchor_sha256": hex.EncodeToString(anchor[:]),
		"roots": b64("../../rust/ti-pki/src/roots-nonprod.json"), "roots_meta": meta,
		"tsl": b64(refList + ".xml"), "tsl_meta": meta,
		"tsl_sig": b64(refList + ".sig"), "tsl_sig_meta": meta,
		"tsl_ocsp": b64(refList + ".ocsp"), "tsl_ocsp_meta": meta,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type answering tipki.RevocationStatus

func (a answering) Check(context.Context, *x509.Certificate, *x509.Certificate, *tipki.TrustStore) (*tipki.RevocationResult, error) {
	return &tipki.RevocationResult{Status: tipki.RevocationStatus(a), RevokedAt: captured.Add(-time.Hour)}, nil
}

func bundleTrust(t *testing.T) (*BundleTrust, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	writeBundle(t, path, captured)
	base, err := newVerifier(EnvironmentReference, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	base.checker = answering(tipki.RevocationGood)
	base.now = func() time.Time { return captured }
	return &BundleTrust{verifier: base, bundlePath: path}, path
}

func idpCertificate(t *testing.T, name string) []*x509.Certificate {
	t.Helper()
	cert, err := tipki.ParseCertificate(readFile(t, "testdata/"+name))
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert}
}

func TestIDPV005TheRealIDPCertificatesAreValidUnderTheRealList(t *testing.T) {
	trust, _ := bundleTrust(t)
	for which, name := range map[IDPCertificate]string{DiscoverySigner: "disc.ru.idp.rise.der", TokenSigner: "main.ru.idp.rise.der"} { //nolint:gosec // file names of test certificates, not credentials
		if err := trust.Check(t.Context(), which, idpCertificate(t, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestIDPV005ARevokedCertificateIsRefused(t *testing.T) {
	trust, _ := bundleTrust(t)
	trust.checker = answering(tipki.RevocationRevoked)
	err := trust.Check(t.Context(), DiscoverySigner, idpCertificate(t, "disc.ru.idp.rise.der"))
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV005ACertificateOfAnotherKindIsRefused(t *testing.T) {
	trust, _ := bundleTrust(t)
	smcb, err := brainpool.ParseCertificatePEM([]byte(idpCertPEM))
	if err != nil {
		t.Fatal(err)
	}
	err = trust.Check(t.Context(), DiscoverySigner, []*x509.Certificate{smcb})
	if err == nil || !strings.Contains(err.Error(), "profile_type_mismatch") {
		t.Errorf("err = %v", err)
	}
}

func TestIDPV005ABundleTooOldRefusesEvenOnceLoaded(t *testing.T) {
	trust, _ := bundleTrust(t)
	certs := idpCertificate(t, "disc.ru.idp.rise.der")
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err != nil {
		t.Fatal(err)
	}
	trust.now = func() time.Time { return captured.Add(tipki.MaxBundleAge) }
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err == nil {
		t.Error("a bundle at the age limit")
	}
}

func TestIDPV005ABadOrMissingBundleDoesNotFallBackToTheLastGoodOne(t *testing.T) {
	trust, path := bundleTrust(t)
	certs := idpCertificate(t, "disc.ru.idp.rise.der")
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err == nil {
		t.Error("a bad bundle")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err == nil {
		t.Error("a missing bundle")
	}
	writeBundle(t, path, captured)
	if err := trust.Check(t.Context(), DiscoverySigner, certs); err != nil {
		t.Errorf("a good bundle again: %v", err)
	}
}

func TestIDPV006TheEnvironmentDecidesWhatIsTrusted(t *testing.T) {
	anchor, signers, err := anchorsFor(EnvironmentProduction)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(anchor, tipki.AnchorProd) || len(signers) != 1 || !slices.Equal(signers[0], tipki.TSLSignerAnchorProd) {
		t.Error("production trusts more than its own anchors")
	}
	for _, env := range []Environment{EnvironmentTest, EnvironmentReference} {
		anchor, signers, err := anchorsFor(env)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(anchor, tipki.AnchorNonProd) || len(signers) != 1 || !slices.Equal(signers[0], tipki.TSLSignerAnchorNonProd) {
			t.Errorf("env %d: not the TEST-ONLY anchors", env)
		}
	}
}

func TestIDPV006NoNamedEnvironmentTrustsNothing(t *testing.T) {
	if _, _, err := anchorsFor(EnvironmentUnset); err == nil {
		t.Error("anchors without an environment")
	}
	for _, name := range []string{"prd", "PROD", "staging"} {
		if env := NewEnvironment(name); env != EnvironmentUnset {
			t.Errorf("%q is environment %d", name, env)
		}
	}
	idp := newFakeIDP(t)
	config := idp.config(&recording{})
	config.Environment = EnvironmentUnset
	if _, err := NewClientFromConfig(config); err == nil {
		t.Error("a client without an environment")
	}
}

func TestIDPV006AProductionTrustRefusesANonProductionBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	writeBundle(t, path, time.Now())
	if _, err := NewBundleTrust(EnvironmentProduction, path, http.DefaultClient); err == nil {
		t.Error("the reference list under production anchors")
	}
}

func TestIDPV003NoBundleNoClient(t *testing.T) {
	idp := newFakeIDP(t)
	config := idp.config(nil)
	config.TrustBundlePath = filepath.Join(t.TempDir(), "none.json")
	if _, err := NewClientFromConfig(config); err == nil {
		t.Error("a bundle that is not there")
	}
}

// The live reference IDP against a bundle `ti pki trust export` wrote, with live OCSP. Gated: `just idpd-trust-test`.
func TestIDPV005TheLiveReferenceIDP(t *testing.T) {
	bundle := os.Getenv("IDPD_TRUST_BUNDLE_PATH")
	if bundle == "" {
		t.Skip("IDPD_TRUST_BUNDLE_PATH not set: needs `ti pki trust export --env ref` and a route to the IDP; proves both IDP certificates live")
	}
	trust, err := NewBundleTrust(EnvironmentReference, bundle, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	recorded := &checked{trust: trust}
	client, err := NewClientFromConfig(ClientConfig{
		Environment: EnvironmentReference, ClientID: "trust-test", RedirectURI: "https://rp/cb",
		Scopes: []string{"openid"}, Trust: recorded,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchSigningKey(t.Context(), client.Metadata.SigningKeyURI, client.httpClient, recorded); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchEncryptionKey(t.Context(), client.Metadata.EncryptionKeyURI, client.httpClient); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(recorded.passed, []IDPCertificate{DiscoverySigner, TokenSigner}) {
		t.Errorf("passed %v", recorded.passed)
	}
	for i, which := range recorded.passed {
		t.Logf("%s: %q valid for an IDP-Dienst (idpd-sig, OCSP)", which, recorded.subjects[i])
	}
	// The same certificates must not pass under production's anchors.
	if _, err := NewBundleTrust(EnvironmentProduction, bundle, http.DefaultClient); err == nil {
		t.Error("a non-production bundle under production anchors")
	}
}

type checked struct {
	trust    CertificateTrust
	passed   []IDPCertificate
	subjects []string
}

func (c *checked) Check(ctx context.Context, which IDPCertificate, certs []*x509.Certificate) error {
	if err := c.trust.Check(ctx, which, certs); err != nil {
		return err
	}
	c.passed = append(c.passed, which)
	c.subjects = append(c.subjects, certs[0].Subject.CommonName)
	return nil
}
