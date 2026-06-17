package testocsp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/internal/testocsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

// newSigner returns a NIST P-256 key + a minimal self-signed cert suitable for
// signing OCSP responses. (Real TI OCSP signers carry id-kp-OCSPSigning EKU;
// we don't strictly need it for the mock to function but it's good hygiene.)
func newSigner(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ocsp-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}

func TestResponder_GoodResponse(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := newSigner(t)

	r := testocsp.NewResponder(t, pki.RCA7.Cert, signKey, signCert)
	r.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{Status: testocsp.StatusGood})

	resp := postOCSPQuery(t, r.URL, pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.Equal(t, ocsp.Good, resp.Status)
	assert.Equal(t, pki.EEZeta.Cert.SerialNumber.Cmp(resp.SerialNumber), 0)
}

func TestResponder_RevokedResponse(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := newSigner(t)

	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	r := testocsp.NewResponder(t, pki.RCA7.Cert, signKey, signCert)
	r.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{
		Status:    testocsp.StatusRevoked,
		RevokedAt: revokedAt,
		Reason:    ocsp.KeyCompromise,
	})

	resp := postOCSPQuery(t, r.URL, pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.Equal(t, ocsp.Revoked, resp.Status)
	assert.Equal(t, ocsp.KeyCompromise, resp.RevocationReason)
	assert.True(t, resp.RevokedAt.Equal(revokedAt), "RevokedAt mismatch: got %v want %v", resp.RevokedAt, revokedAt)
}

func TestResponder_UnknownByDefault(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := newSigner(t)

	// No Set call — responder defaults to Unknown.
	r := testocsp.NewResponder(t, pki.RCA7.Cert, signKey, signCert)

	resp := postOCSPQuery(t, r.URL, pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	assert.Equal(t, ocsp.Unknown, resp.Status)
}

func TestResponder_FailAfter(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := newSigner(t)

	r := testocsp.NewResponder(t, pki.RCA7.Cert, signKey, signCert)
	r.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{Status: testocsp.StatusGood})
	r.SetFailAfter(2)

	// First request succeeds.
	_ = postOCSPQuery(t, r.URL, pki.EEZeta.Cert, pki.SubCAKomp.Cert)

	// Second request: 500.
	reqBody, err := ocsp.CreateRequest(pki.EEZeta.Cert, pki.SubCAKomp.Cert, nil)
	require.NoError(t, err)
	httpResp, err := http.Post(r.URL, "application/ocsp-request", strings.NewReader(string(reqBody))) //nolint:noctx,bodyclose // test-only against httptest.Server; body closed via defer below
	require.NoError(t, err)
	defer httpResp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, httpResp.StatusCode)

	assert.Equal(t, 2, r.RequestCount())
}

// postOCSPQuery sends a parsed-and-verified OCSP request to the mock and
// returns the parsed response. It fails the test on any wire/parse error.
func postOCSPQuery(t *testing.T, url string, leaf, issuer *x509.Certificate) *ocsp.Response {
	t.Helper()
	reqBody, err := ocsp.CreateRequest(leaf, issuer, nil)
	require.NoError(t, err)
	httpResp, err := http.Post(url, "application/ocsp-request", strings.NewReader(string(reqBody))) //nolint:noctx // test-only against httptest.Server
	require.NoError(t, err)
	defer httpResp.Body.Close()
	require.Equal(t, http.StatusOK, httpResp.StatusCode, "unexpected HTTP status")
	respBody, err := io.ReadAll(httpResp.Body)
	require.NoError(t, err)
	resp, err := ocsp.ParseResponse(respBody, nil)
	require.NoError(t, err)
	return resp
}
