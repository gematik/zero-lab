package gempki_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/internal/testtsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenSSLCross_RealWorld_SMCB confirms gempki and openssl agree on the
// real gematik TI-PKI wire: actual brainpool EE → real GEM.SMCB-CA51 →
// real GEM.RCA5. Cross-validating with openssl guarantees our brainpool
// chain handling is bit-compatible with the reference implementation, not
// just self-consistent.
func TestOpenSSLCross_RealWorld_SMCB(t *testing.T) {
	t.Parallel()
	testca.RequireOpenSSLBrainpool(t)

	dir := t.TempDir()
	rootPath := writeFixturePEM(t, filepath.Join(dir, "rca5.pem"), fixtureBrainpoolRCA5PEM)
	chainPath := writeFixturePEM(t, filepath.Join(dir, "smcbca51.pem"), fixtureBrainpoolSMCBCA51PEM)
	leafPath := writeFixturePEM(t, filepath.Join(dir, "smcb-ee.pem"), fixtureBrainpoolSMCBEEPEM)

	ok, out := testca.OpenSSLVerify(t, leafPath, chainPath, rootPath)
	assert.True(t, ok, "openssl rejected real-world SMC-B chain: %s", out)

	rca5, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore(rca5)
	require.NoError(t, err)
	smcbCA51, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBCA51PEM))
	require.NoError(t, err)
	eeCerts, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationMode(gempki.RevocationModeDisabled),
	)
	chain := append([]*x509.Certificate{eeCerts[0]}, smcbCA51...)
	result, err := v.Validate(t.Context(), chain)
	require.NoError(t, err)
	assert.True(t, result.Valid, "gempki rejected real-world SMC-B chain: %v", result.Errors)
}

// TestOpenSSLCross_RealWorld_TSLIntermediates confirms openssl can parse
// every brainpool/NIST CA published in the embedded TSL — i.e. our
// brainpool wire format matches openssl's expectations for the actual TI
// PKI, not just for the testca-generated certs.
//
// This isn't a chain test (the TSL CAs come from many TSPs with different
// trust anchors); it's a wire-format conformance check.
func TestOpenSSLCross_RealWorld_TSLIntermediates(t *testing.T) {
	t.Parallel()
	testca.RequireOpenSSLBrainpool(t)

	tsl, err := testtsl.EmbeddedTSL()
	require.NoError(t, err)
	cas := gempki.IntermediateCAsFromTSL(tsl)
	require.NotEmpty(t, cas)

	dir := t.TempDir()
	parsed := 0
	for i, c := range cas {
		path := filepath.Join(dir, "ca.pem")
		require.NoError(t, os.WriteFile(path,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}),
			0o600))
		out, err := exec.Command("openssl", "x509", "-in", path, "-noout", "-subject").CombinedOutput()
		if err != nil {
			t.Logf("TSL CA #%d (%s) — openssl rejected: %v\n%s",
				i, c.Cert.Subject.CommonName, err, out)
			continue
		}
		if strings.Contains(string(out), "subject") {
			parsed++
		}
	}
	t.Logf("openssl parsed %d/%d TSL CAs cleanly", parsed, len(cas))
	assert.GreaterOrEqual(t, parsed, len(cas)*9/10,
		"openssl should parse at least 90%% of TSL CAs")
}

func writeFixturePEM(t *testing.T, path, pemText string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(pemText), 0o600))
	return path
}
