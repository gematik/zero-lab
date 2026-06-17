package gempki_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/internal/testocsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenSSLCross_OCSP_GoodResponseSmokeTest confirms our mock responder
// emits a wire-compatible OCSP response: openssl ocsp drives the full
// query/verify cycle and must agree with our Status=Good entry.
//
// NIST-only — the testocsp responder doesn't sign with Brainpool yet (see
// the package comment in internal/testocsp). When that lands, this test
// can be parametrised over the curve.
func TestOpenSSLCross_OCSP_GoodResponseSmokeTest(t *testing.T) {
	t.Parallel()
	testca.RequireOpenSSL(t)

	pki, err := testca.New()
	require.NoError(t, err)

	// Issuer signs OCSP responses directly (no delegation).
	resp := testocsp.NewResponder(t, pki.SubCAKomp.Cert, pki.SubCAKomp.Key, pki.SubCAKomp.Cert)
	resp.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{Status: testocsp.StatusGood})

	issuerPath := testca.WritePEMCert(t, "issuer.pem", pki.SubCAKomp)
	leafPath := testca.WritePEMCert(t, "leaf.pem", pki.EEZeta)
	rootPath := testca.WritePEMCert(t, "root.pem", pki.RCA7)

	// -no_nonce: skip nonce-echo policy (our responder doesn't echo yet).
	// -url: drive the full request/response/verify cycle.
	cmd := exec.Command(
		"openssl", "ocsp",
		"-issuer", issuerPath,
		"-cert", leafPath,
		"-url", resp.URL,
		"-CAfile", rootPath,
		"-VAfile", issuerPath,
		"-no_nonce",
	)
	out, err := cmd.CombinedOutput()
	text := string(out)
	require.NoError(t, err, "openssl ocsp output: %s", text)

	// Two things must appear: the response itself must verify, and the
	// per-cert status must say "good".
	assert.Contains(t, text, "Response verify OK", "openssl rejected response: %s", text)
	assert.True(t,
		strings.Contains(text, ": good") || strings.Contains(text, " good"),
		"openssl did not report status=good: %s", text)
}
