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

package vau

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6960's CertID hash, as TI responders use it.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPKI is a CA and the VAU certificate it issued, both P-256: the checks of the vau
// package do not depend on the curve, and the chain is the verifier's business.
type testPKI struct {
	caKey   *ecdsa.PrivateKey
	ca      *x509.Certificate
	vauKey  *ecdsa.PrivateKey
	vauCert *x509.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vauKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Komp-CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	vauTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234), Subject: pkix.Name{CommonName: "Test VAU"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	vauDER, err := x509.CreateCertificate(rand.Reader, vauTemplate, ca, &vauKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	vauCert, err := x509.ParseCertificate(vauDER)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{caKey: caKey, ca: ca, vauKey: vauKey, vauCert: vauCert}
}

// ocspStatus is the certStatus of a single response: good [0], revoked [1] or unknown [2].
type ocspStatus int

const (
	ocspGood ocspStatus = iota
	ocspRevoked
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type ocspExtension struct {
	ID    asn1.ObjectIdentifier
	Value []byte
}

type ocspCertID struct {
	HashAlgorithm algorithmIdentifier
	NameHash      []byte
	KeyHash       []byte
	Serial        *big.Int
}

type ocspSingleResponse struct {
	CertID     ocspCertID
	Status     asn1.RawValue
	ThisUpdate time.Time       `asn1:"generalized"`
	Extensions []ocspExtension `asn1:"explicit,tag:1"`
}

type ocspResponseData struct {
	ResponderID asn1.RawValue
	ProducedAt  time.Time `asn1:"generalized"`
	Responses   []ocspSingleResponse
}

type ocspBasicResponse struct {
	TBS       asn1.RawValue
	Algorithm algorithmIdentifier
	Signature asn1.BitString
}

type ocspResponseBytes struct {
	Type     asn1.ObjectIdentifier
	Response []byte
}

type ocspResponse struct {
	Status asn1.Enumerated
	Bytes  ocspResponseBytes `asn1:"explicit,tag:0"`
}

func mustMarshal(t *testing.T, v any, params ...string) []byte {
	t.Helper()
	der, err := asn1.MarshalWithParams(v, strings.Join(params, ","))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// stapledOCSP is the response the CA signs on the VAU certificate, as an Aktensystem staples
// it: issued by the CA itself, with gemSpec_PKI's certHash extension.
func (p *testPKI) stapledOCSP(t *testing.T, status ocspStatus, producedAt time.Time) []byte {
	t.Helper()
	nullParams := asn1.RawValue{Tag: asn1.TagNull}
	sha1OID := asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(p.ca.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	nameHash := sha1.Sum(p.ca.RawSubject) //nolint:gosec // See the import.
	keyHash := sha1.Sum(spki.Key.Bytes)   //nolint:gosec // See the import.
	certHash := sha256.Sum256(p.vauCert.Raw)
	certHashValue := mustMarshal(t, struct {
		Algorithm algorithmIdentifier
		Hash      []byte
	}{algorithmIdentifier{Algorithm: sha256OID}, certHash[:]})

	statusValue := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0}
	if status == ocspRevoked {
		statusValue = asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true,
			Bytes: mustMarshal(t, producedAt.Add(-time.Hour).UTC(), "generalized"),
		}
	}
	tbs := mustMarshal(t, ocspResponseData{
		ResponderID: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: p.ca.RawSubject},
		ProducedAt:  producedAt.UTC().Truncate(time.Second),
		Responses: []ocspSingleResponse{{
			CertID: ocspCertID{
				HashAlgorithm: algorithmIdentifier{Algorithm: sha1OID, Parameters: nullParams},
				NameHash:      nameHash[:], KeyHash: keyHash[:], Serial: p.vauCert.SerialNumber,
			},
			Status:     statusValue,
			ThisUpdate: producedAt.UTC().Truncate(time.Second),
			Extensions: []ocspExtension{{ID: asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}, Value: certHashValue}},
		}},
	})
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, p.caKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	basic := mustMarshal(t, ocspBasicResponse{
		TBS:       asn1.RawValue{FullBytes: tbs},
		Algorithm: algorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		Signature: asn1.BitString{Bytes: signature, BitLength: 8 * len(signature)},
	})
	return mustMarshal(t, ocspResponse{Bytes: ocspResponseBytes{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}, Response: basic}})
}

// fakeVerifier stands for the ti tool: it gives the verdict it is told.
type fakeVerifier struct {
	chainValid, signatureValid bool
	// profile and environment are what it reports; empty is the VAU profile and the
	// reference environment.
	profile, environment string
	err                  error
	calls                int
}

func (f *fakeVerifier) VerifyVAU(context.Context, *CertData, []byte, []byte) (*Verdict, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	verdict := &Verdict{
		ChainValid: f.chainValid, SignatureValid: f.signatureValid, ChainErrors: []string{"test"},
		Profile: VAUCertificateProfile, Environment: "ref",
	}
	if f.profile != "" {
		verdict.Profile = f.profile
	}
	if f.environment != "" {
		verdict.Environment = f.environment
	}
	return verdict, nil
}

// keysFixture is a test VAU whose signed keys hold every check of A_24624, until a test
// changes them.
type keysFixture struct {
	pki      *testPKI
	server   *Server
	keys     *SignedPublicVAUKeys
	certData []byte
	// certDataHandler, when set, answers the CertData request instead.
	certDataHandler http.HandlerFunc

	mu        sync.Mutex
	message3s int
}

func newKeysFixture(t *testing.T) *keysFixture {
	t.Helper()
	server, err := NewServer()
	if err != nil {
		t.Fatal(err)
	}
	pki := newTestPKI(t)
	now := time.Now()
	f := &keysFixture{pki: pki, server: server, keys: server.signedPublicKeys}
	f.keys.SignedPubKeys.IssuedAt = now.Unix()
	f.keys.SignedPubKeys.ExpiresAt = now.Add(time.Hour).Unix()
	certHash := sha256.Sum256(pki.vauCert.Raw)
	f.keys.CertHash = certHash[:]
	f.keys.Cdv = 1
	f.keys.OcspResponse = pki.stapledOCSP(t, ocspGood, now.Add(-time.Hour))
	f.certData, err = encMode.Marshal(CertData{Cert: pki.vauCert.Raw, CA: pki.ca.Raw, RCAChain: [][]byte{pki.ca.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// sign signs the keys as they are now and sets them as the server's.
func (f *keysFixture) sign(t *testing.T) {
	t.Helper()
	var err error
	if f.keys.SignedPubKeysRaw, err = encMode.Marshal(f.keys.SignedPubKeys); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.keys.SignedPubKeysRaw)
	r, s, err := ecdsa.Sign(rand.Reader, f.pki.vauKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	f.keys.Signature = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	if f.server.signedPublicKeysRaw, err = encMode.Marshal(f.keys); err != nil {
		t.Fatal(err)
	}
}

func (f *keysFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/CertData.") {
		if f.certDataHandler != nil {
			f.certDataHandler(w, r)
			return
		}
		if r.URL.Path != fmt.Sprintf("/CertData.%x-%d", sha256.Sum256(f.pki.vauCert.Raw), 1) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(f.certData)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path != "/VAU" && r.Header.Get("Content-Type") == "application/cbor" {
		f.mu.Lock()
		f.message3s++
		f.mu.Unlock()
	}
	f.server.ServeHTTP(w, r)
}

// open signs the keys and runs a handshake against the fixture.
func (f *keysFixture) open(ctx context.Context, t *testing.T, verifier CertVerifier, mode VerifyMode) (*Channel, error) {
	t.Helper()
	f.sign(t)
	stub := httptest.NewServer(f)
	t.Cleanup(stub.Close)
	return OpenChannelContext(ctx, ChannelConfig{BaseURL: stub.URL, Env: EnvNonPU, HTTPClient: stub.Client(), Verifier: verifier, Mode: mode})
}

// refused asserts that an enforced handshake is refused with ErrServerKeys for the reason
// given, before Message3.
func (f *keysFixture) refused(t *testing.T, reason string) {
	t.Helper()
	_, err := f.open(context.Background(), t, &fakeVerifier{chainValid: true, signatureValid: true}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("err = %v, want %q", err, reason)
	}
	if f.message3s != 0 {
		t.Errorf("Message3 sent %d times", f.message3s)
	}
}

func TestA_24624_KeysThatHoldEveryCheckAreTaken(t *testing.T) {
	f := newKeysFixture(t)
	verifier := &fakeVerifier{chainValid: true, signatureValid: true}
	if _, err := f.open(context.Background(), t, verifier, VerifyEnforce); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 {
		t.Errorf("verifier called %d times", verifier.calls)
	}
}

func TestA_24624_AnEmptyCertHashIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	f.keys.CertHash = nil
	f.refused(t, "cert_hash: empty")
}

func TestA_24624_ACertHashThatIsNotTheCertificatesIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	other := sha256.Sum256(f.pki.ca.Raw)
	f.keys.CertHash = other[:]
	// The Aktensystem serves the VAU certificate under another certificate's hash.
	f.certDataHandler = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(f.certData) }
	f.refused(t, "cert_hash: not the SHA-256 of the CertData certificate")
}

func TestA_24624_KeysPastTheirExpiryAreRefused(t *testing.T) {
	f := newKeysFixture(t)
	f.keys.SignedPubKeys.ExpiresAt = time.Now().Unix()
	f.refused(t, "exp: not after now")
}

func TestA_24624_AMissingOCSPResponseIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	f.keys.OcspResponse = nil
	f.refused(t, "ocsp_response: missing")
}

func TestA_24624_AnOCSPResponseThatIsNotGoodIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	f.keys.OcspResponse = f.pki.stapledOCSP(t, ocspRevoked, time.Now().Add(-time.Hour))
	f.refused(t, "ocsp_response: status revoked, not good")
}

func TestA_24624_AnOCSPResponseOlderThan24HoursIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	f.keys.OcspResponse = f.pki.stapledOCSP(t, ocspGood, time.Now().Add(-maxOCSPAge-time.Minute))
	f.refused(t, "ocsp_response: status unknown, or outside its time window")
}

func TestA_24624_AnOCSPResponseForAnotherCertificateIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	other := newKeysFixture(t)
	f.keys.OcspResponse = other.pki.stapledOCSP(t, ocspGood, time.Now().Add(-time.Hour))
	f.refused(t, "ocsp_response: ")
}

// A CA of the peer's making, named like the real one, cannot vouch for a certificate it did
// not issue with a "good" response of its own.
func TestA_24624_AnOCSPResponseOfACAThatDidNotIssueTheCertificateIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	other := newTestPKI(t)
	forged := &testPKI{caKey: other.caKey, ca: other.ca, vauCert: f.pki.vauCert}
	f.keys.OcspResponse = forged.stapledOCSP(t, ocspGood, time.Now().Add(-time.Hour))
	var err error
	if f.certData, err = encMode.Marshal(CertData{Cert: f.pki.vauCert.Raw, CA: other.ca.Raw}); err != nil {
		t.Fatal(err)
	}
	f.refused(t, "ocsp_response: not checked, the CertData CA did not issue the certificate")
}

func TestA_24624_ACertificateOfAnotherProfileIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	_, err := f.open(context.Background(), t, &fakeVerifier{chainValid: true, signatureValid: true, profile: "smcb-aut"}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), "profile: not epa-vau-aut") || f.message3s != 0 {
		t.Fatalf("err = %v, Message3 %d", err, f.message3s)
	}
}

func TestA_24624_ACertificateOfAnotherEnvironmentIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	_, err := f.open(context.Background(), t, &fakeVerifier{chainValid: true, signatureValid: true, environment: "prod"}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), "environment: ") || f.message3s != 0 {
		t.Fatalf("err = %v, Message3 %d", err, f.message3s)
	}
	for _, c := range []struct {
		verified string
		env      Env
		want     bool
	}{
		{"prod", EnvPU, true},
		{"ref", EnvPU, false},
		{"", EnvPU, false},
		{"ref", EnvNonPU, true},
		{"test", EnvNonPU, true},
		{"prod", EnvNonPU, false},
		{"", EnvNonPU, false},
	} {
		if got := environmentMatches(c.verified, c.env); got != c.want {
			t.Errorf("%q for %d: %v", c.verified, c.env, got)
		}
	}
}

func TestA_24624_AChainTheVerifierRefusesIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	_, err := f.open(context.Background(), t, &fakeVerifier{chainValid: false, signatureValid: true}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), "chain: not valid") || f.message3s != 0 {
		t.Fatalf("err = %v, Message3 %d", err, f.message3s)
	}
}

func TestA_24624_ASignatureTheVerifierRefusesIsRefused(t *testing.T) {
	f := newKeysFixture(t)
	_, err := f.open(context.Background(), t, &fakeVerifier{chainValid: true, signatureValid: false}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), "signature: not valid") || f.message3s != 0 {
		t.Fatalf("err = %v, Message3 %d", err, f.message3s)
	}
}

func TestA_24624_AVerifierThatCannotJudgeRefuses(t *testing.T) {
	f := newKeysFixture(t)
	_, err := f.open(context.Background(), t, &fakeVerifier{err: errors.New("ti not found")}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || f.message3s != 0 {
		t.Fatalf("err = %v, Message3 %d", err, f.message3s)
	}
}

// The CertData request runs under the handshake's context, and its body is bounded.
func TestA_24624_TheCertDataFetchIsBoundInTimeAndSize(t *testing.T) {
	f := newKeysFixture(t)
	f.certDataHandler = func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := f.open(ctx, t, &fakeVerifier{chainValid: true, signatureValid: true}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), "CertData: getting it") {
		t.Errorf("context: err = %v", err)
	}

	f = newKeysFixture(t)
	f.certDataHandler = func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, maxMessageSize+1)) }
	_, err = f.open(context.Background(), t, &fakeVerifier{chainValid: true, signatureValid: true}, VerifyEnforce)
	if !errors.Is(err, ErrServerKeys) || !strings.Contains(err.Error(), ErrBodyTooLarge.Error()) {
		t.Errorf("size: err = %v", err)
	}
}

// warnings collects the warnings logged while a test runs.
type warnings struct {
	mu      sync.Mutex
	records []slog.Record
}

func (w *warnings) Enabled(_ context.Context, level slog.Level) bool { return level >= slog.LevelWarn }

func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, r)
	return nil
}

func (w *warnings) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnings) WithGroup(string) slog.Handler      { return w }

func captureWarnings(t *testing.T) *warnings {
	t.Helper()
	w := &warnings{}
	previous := slog.Default()
	slog.SetDefault(slog.New(w))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return w
}

// keyWarnings are the warnings about the signed keys, each with its text and attributes.
func (w *warnings) keyWarnings() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var found []string
	for _, r := range w.records {
		if !strings.HasPrefix(r.Message, "VAU signed keys") {
			continue
		}
		text := r.Message
		r.Attrs(func(a slog.Attr) bool {
			text += " " + a.String()
			return true
		})
		found = append(found, text)
	}
	return found
}

// Maintainer, 2026-11-16: verification is optional. In warn mode the handshake goes on, and
// one warning names every check that did not hold.
func TestA_24624_WarnModeLogsOneWarningNamingWhatFailed(t *testing.T) {
	w := captureWarnings(t)
	f := newKeysFixture(t)
	f.keys.SignedPubKeys.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	f.keys.OcspResponse = nil
	verifier := &fakeVerifier{chainValid: false, signatureValid: false, profile: "smcb-aut", environment: "prod"}
	if _, err := f.open(context.Background(), t, verifier, VerifyWarn); err != nil {
		t.Fatal(err)
	}
	found := w.keyWarnings()
	if len(found) != 1 {
		t.Fatalf("warnings = %q", found)
	}
	for _, check := range []string{"exp: not after now", "ocsp_response: missing", "chain: not valid", "signature: not valid", "profile: not epa-vau-aut", "environment: "} {
		if !strings.Contains(found[0], check) {
			t.Errorf("warning lacks %q: %s", check, found[0])
		}
	}
	if strings.Contains(found[0], "cert_hash") {
		t.Errorf("warning names a check that held: %s", found[0])
	}
}

func TestA_24624_WithoutAVerifierOrWithModeOffOneWarningSaysWhatWasNotChecked(t *testing.T) {
	for name, run := range map[string]struct {
		verifier CertVerifier
		mode     VerifyMode
		want     string
	}{
		"no verifier, enforce": {nil, VerifyEnforce, "chain, signature, profile and environment: not checked, no verifier configured"},
		"no verifier, warn":    {nil, VerifyWarn, "chain, signature, profile and environment: not checked, no verifier configured"},
		"off":                  {&fakeVerifier{}, VerifyOff, "verification is off"},
	} {
		t.Run(name, func(t *testing.T) {
			w := captureWarnings(t)
			f := newKeysFixture(t)
			f.keys.CertHash = nil
			if _, err := f.open(context.Background(), t, run.verifier, run.mode); err != nil {
				t.Fatal(err)
			}
			found := w.keyWarnings()
			if len(found) != 1 || !strings.Contains(found[0], run.want) {
				t.Fatalf("warnings = %q", found)
			}
		})
	}
}
