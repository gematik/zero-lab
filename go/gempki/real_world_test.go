package gempki_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real-world integration tests against actual gematik-published artifacts:
//
//   - the test-environment roots.json (embedded as roots-test.json,
//     loaded via [gempki.EmbeddedLoader])
//   - a TSL snapshot (embedded in tsl_embed.go from
//     testdata/tsl-test.xml — gematik test environment,
//     sequence 10687)
//   - a real brainpool SMC-B end-entity certificate (Arztpraxis Bernd
//     Rosenstrauch TEST-ONLY) signed by GEM.SMCB-CA5 → GEM.RCA5
//
// These tests prove the full stack works on actual TI wire data, not just
// synthetic testca PKIs.

// TestRealWorld_EmbeddedTestRootsLoad confirms the embedded-loader path
// works end-to-end on real roots.json data. It also documents a known
// limitation: the A_28419 cross-cert walk stops the first time it
// encounters an RSA-signed cross-cert, which on the test environment means
// only the current anchor (RCA8) and its forward successors end up in the
// store. Pre-RCA8 ECC roots like RCA5 are not reachable via the strict
// walk and must be loaded another way (e.g. via [NewTrustStore] from a
// caller-supplied PEM list).
func TestRealWorld_EmbeddedTestRootsLoad(t *testing.T) {
	t.Parallel()

	ts, err := gempki.EmbeddedLoader{Env: gempki.EnvTest}.Load(t.Context())
	require.NoError(t, err)
	require.GreaterOrEqual(t, ts.Len(), 1)
	t.Logf("trust store from EmbeddedLoader{EnvTest} has %d root(s)", ts.Len())

	anchor, err := gempki.EmbeddedTrustAnchor(gempki.EnvTest)
	require.NoError(t, err)
	bySKI, ok := ts.BySKI(anchor.SubjectKeyId)
	require.True(t, ok, "anchor must be retrievable by SKI")
	assert.True(t, bySKI.Equal(anchor))

	byCN, ok := ts.ByCommonName(anchor.Subject.CommonName)
	require.True(t, ok, "anchor must be retrievable by CommonName")
	assert.True(t, byCN.Equal(anchor))
}

// TestRealWorld_TSLParsesAndPublishesCAs confirms the TSL XML wire format
// is parseable end-to-end and produces a credible volume of CA candidates.
// Doesn't check the TSL signature (gempki.tsl.go's signature verification
// is a known TODO); for the integration here we're concerned with parsing
// + structural extraction, not trust attestation.
func TestRealWorld_TSLParsesAndPublishesCAs(t *testing.T) {
	t.Parallel()

	tsl, err := gempki.EmbeddedTestTSL()
	require.NoError(t, err)
	require.NotNil(t, tsl)
	assert.Equal(t, "TEST-ONLY gematik GmbH",
		string(tsl.SchemeInformation.SchemeOperatorName[0].Value))

	cas := gempki.IntermediateCAsFromTSL(tsl)
	require.NotEmpty(t, cas)
	t.Logf("TSL publishes %d CA/PKC service certs", len(cas))

	// The fixture EE was issued by a CA whose CN contains "SMCB-CA5".
	// We don't insist the EE's *exact* issuer is in the TSL — TSP rotations
	// happen — but at least one SMC-B-flavoured CA should be present.
	var anySMCB bool
	for _, c := range cas {
		if strings.Contains(c.Cert.Subject.CommonName, "SMCB") {
			anySMCB = true
			break
		}
	}
	assert.True(t, anySMCB, "TSL must publish at least one SMC-B CA")
}

// TestRealWorld_SMCBValidatesEndToEnd walks a complete real-world chain:
// real EE → real SubCA → real root. The SubCA comes from gempki's
// inline PEM fixture (the gematik publishes both this cert and the
// matching RCA5 root), reflecting the realistic flow where a TLS
// handshake supplies the SubCA alongside the EE. The TSL CAs are also
// passed as candidate intermediates so the chain builder has the full
// real-world choice surface to navigate.
func TestRealWorld_SMCBValidatesEndToEnd(t *testing.T) {
	t.Parallel()

	// Trust anchor: real GEM.RCA5 TEST-ONLY (published by gematik in the
	// roots distribution, brainpool P-256r1). We load via PEM fixture so
	// we deliberately bypass the EmbeddedLoader's A_28419 walk — see the
	// limitation documented above.
	rca5, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore(rca5)
	require.NoError(t, err)

	// Intermediates: real GEM.SMCB-CA5 (matching the EE's issuer) PLUS
	// every CA published in the TSL. BuildChain picks the right one by
	// SKI/AKI; the TSL CAs are present to confirm the chain builder
	// navigates a realistic candidate set, not just a hand-picked SubCA.
	smcbCA51, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBCA51PEM))
	require.NoError(t, err)
	tsl, err := gempki.EmbeddedTestTSL()
	require.NoError(t, err)
	tslCAs := gempki.IntermediateCAsFromTSL(tsl)
	intermediates := smcbCA51
	for _, c := range tslCAs {
		intermediates = append(intermediates, c.Cert)
	}
	t.Logf("validation considers %d candidate intermediates", len(intermediates))

	eeCerts, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)
	require.Len(t, eeCerts, 1)
	ee := eeCerts[0]

	v := gempki.NewValidator(
		gempki.WithTrustStore(ts),
		gempki.WithRevocationMode(gempki.RevocationModeDisabled),
	)
	chain := append([]*x509.Certificate{ee}, intermediates...)
	result, err := v.Validate(t.Context(), chain)
	require.NoError(t, err)
	assert.True(t, result.Valid, "real-world SMC-B chain failed: %v", result.Errors)

	// On success result.Chain is the BUILT chain.
	require.Len(t, result.Chain, 3)
	t.Logf("validated chain: %s → %s → %s",
		result.Chain[0].Subject.CommonName,
		result.Chain[1].Subject.CommonName,
		result.Chain[2].Subject.CommonName)
}

// TestRealWorld_ProfileSMCBAuthAcceptsRealCert confirms ProfileSMCBAuth's
// pre-wired constraints (digitalSignature KU, clientAuth EKU, SMC-B
// institution role OIDs, OIDPolicyGemOrCP) match the real SMC-B Arzt cert.
func TestRealWorld_ProfileSMCBAuthAcceptsRealCert(t *testing.T) {
	t.Parallel()

	rca5, _ := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolRCA5PEM))
	ts, err := gempki.NewTrustStore(rca5)
	require.NoError(t, err)

	smcbCA51, _ := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBCA51PEM))
	eeCerts, _ := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	ee := eeCerts[0]

	v := gempki.ProfileSMCBAuth(ts)
	gempki.WithRevocationMode(gempki.RevocationModeDisabled)(v)

	chain := append([]*x509.Certificate{ee}, smcbCA51...)
	result, err := v.Validate(t.Context(), chain)
	require.NoError(t, err)
	assert.True(t, result.Valid, "ProfileSMCBAuth rejected a real SMC-B cert: %v", result.Errors)
}
