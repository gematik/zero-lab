package gempki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestCert produces a self-signed ECDSA P-256 cert with the supplied
// policy OIDs and admission profession OIDs. KeyUsage / EKU are taken from
// the options. Used by every cert_type test to construct discriminator
// inputs without pulling in the heavier testca PKI.
type buildOpts struct {
	policies       []asn1.ObjectIdentifier
	professionOIDs []asn1.ObjectIdentifier
	keyUsage       x509.KeyUsage
	ekus           []x509.ExtKeyUsage
}

func buildTestCert(t *testing.T, opts buildOpts) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	// Go 1.22+ deprecates PolicyIdentifiers on CreateCertificate; the new
	// Policies field with x509.OID is what gets honored. Convert here so
	// the certificate actually ends up carrying the policies we asked for.
	var policies []x509.OID
	for _, p := range opts.policies {
		ints := make([]uint64, len(p))
		for i, n := range p {
			ints[i] = uint64(n) //nolint:gosec // OID arcs are positive
		}
		o, err := x509.OIDFromInts(ints)
		require.NoError(t, err)
		policies = append(policies, o)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().UnixNano())),
		Subject:      pkix.Name{CommonName: "TEST-EE"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     opts.keyUsage,
		ExtKeyUsage:  opts.ekus,
		Policies:     policies,
	}
	if len(opts.professionOIDs) > 0 {
		ext, err := encodeAdmissionExtension(opts.professionOIDs)
		require.NoError(t, err)
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// encodeAdmissionExtension builds a minimal AdmissionSyntax with a single
// ProfessionInfo carrying the supplied OIDs. Mirrors the parser shape in
// gempki/admission_statement.go.
func encodeAdmissionExtension(oids []asn1.ObjectIdentifier) (pkix.Extension, error) {
	type professionInfo struct {
		ProfessionItems []string                `asn1:"directory,sequence"`
		ProfessionOids  []asn1.ObjectIdentifier `asn1:"optional,sequence"`
	}
	type admissions struct {
		ProfessionInfos []professionInfo
	}
	type admissionSyntax struct {
		ContentsOfAdmissions []admissions
	}
	v := admissionSyntax{
		ContentsOfAdmissions: []admissions{{
			ProfessionInfos: []professionInfo{{
				ProfessionItems: []string{"TEST-ROLE"},
				ProfessionOids:  oids,
			}},
		}},
	}
	raw, err := asn1.Marshal(v)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3},
		Value: raw,
	}, nil
}

func TestDetectCertificateType_PolicyMatches(t *testing.T) {
	t.Parallel()
	type tc struct {
		name  string
		typed gempki.CertificateType
	}
	cases := []tc{
		{"eGK QES", gempki.CertTypeChQES},
		{"eGK AUT", gempki.CertTypeChAUT},
		{"HBA QES", gempki.CertTypeHpQES},
		{"HBA AUT", gempki.CertTypeHpAUT},
		{"HBA ENC", gempki.CertTypeHpENC},
		{"SMC-B AUT", gempki.CertTypeHciAUT},
		{"SMC-B ENC", gempki.CertTypeHciENC},
		{"SMC-B OSIG", gempki.CertTypeHciOSIG},
		{"FD TLS-S", gempki.CertTypeFdTLSS},
		{"FD TLS-C", gempki.CertTypeFdTLSC},
		{"FD SIG", gempki.CertTypeFdSIG},
		{"FD ENC", gempki.CertTypeFdENC},
		{"FD AUT", gempki.CertTypeFdAUT},
		{"FD OSIG", gempki.CertTypeFdOSIG},
		{"ZD TLS-S", gempki.CertTypeZdTLSS},
		{"ZD SIG", gempki.CertTypeZdSIG},
		{"HSK SIG", gempki.CertTypeHskSIG},
		{"HSK ENC", gempki.CertTypeHskENC},
		{"GemVER", gempki.CertTypeGemVER},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := buildTestCert(t, buildOpts{
				policies: []asn1.ObjectIdentifier{
					gempki.OIDPolicyGemOrCP,
					c.typed.OID(),
				},
				keyUsage: x509.KeyUsageDigitalSignature,
			})
			got := gempki.DetectCertificateType(cert)
			assert.Equal(t, c.typed, got)
		})
	}
}

func TestDetectCertificateType_AdmissionFallback(t *testing.T) {
	t.Parallel()
	type tc struct {
		name       string
		professOID asn1.ObjectIdentifier
		ku         x509.KeyUsage
		want       gempki.CertificateType
	}
	cases := []tc{
		{"SMC-B Krankenhaus AUT (digitalSignature)",
			gempki.OIDInstKrankenhaus, x509.KeyUsageDigitalSignature, gempki.CertTypeHciAUT},
		{"SMC-B Apotheke ENC (keyEncipherment)",
			gempki.OIDInstOeffentlicheApo, x509.KeyUsageKeyEncipherment, gempki.CertTypeHciENC},
		{"SMC-B Praxis OSIG (contentCommitment)",
			gempki.OIDInstArztpraxis, x509.KeyUsageContentCommitment, gempki.CertTypeHciOSIG},
		{"HBA Arzt QES (contentCommitment)",
			gempki.OIDProfArzt, x509.KeyUsageContentCommitment, gempki.CertTypeHpQES},
		{"HBA Apotheker AUT (digitalSignature)",
			gempki.OIDProfApotheker, x509.KeyUsageDigitalSignature, gempki.CertTypeHpAUT},
		{"HBA Zahnarzt ENC (keyEncipherment)",
			gempki.OIDProfZahnarzt, x509.KeyUsageKeyEncipherment, gempki.CertTypeHpENC},
		{"eGK Versicherter AUT",
			gempki.OIDProfVersicherter, x509.KeyUsageDigitalSignature, gempki.CertTypeChAUT},
		{"eGK Versicherter QES",
			gempki.OIDProfVersicherter, x509.KeyUsageContentCommitment, gempki.CertTypeChQES},
		{"eGK Versicherter ENC",
			gempki.OIDProfVersicherter, x509.KeyUsageKeyEncipherment, gempki.CertTypeChENC},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := buildTestCert(t, buildOpts{
				professionOIDs: []asn1.ObjectIdentifier{c.professOID},
				keyUsage:       c.ku,
				// no policies — force the Admission fallback
			})
			got := gempki.DetectCertificateType(cert)
			assert.Equal(t, c.want, got, "Admission %s + KeyUsage %#x → %s", c.professOID, c.ku, c.want)
		})
	}
}

func TestDetectCertificateType_NoMatch(t *testing.T) {
	t.Parallel()
	t.Run("only umbrella policy, no Admission", func(t *testing.T) {
		cert := buildTestCert(t, buildOpts{
			policies: []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP},
			keyUsage: x509.KeyUsageDigitalSignature,
		})
		assert.Equal(t, gempki.CertTypeUnknown, gempki.DetectCertificateType(cert))
	})
	t.Run("nil cert", func(t *testing.T) {
		assert.Equal(t, gempki.CertTypeUnknown, gempki.DetectCertificateType(nil))
	})
	t.Run("unrelated admission OID", func(t *testing.T) {
		cert := buildTestCert(t, buildOpts{
			professionOIDs: []asn1.ObjectIdentifier{{1, 2, 3, 4, 5}},
			keyUsage:       x509.KeyUsageDigitalSignature,
		})
		assert.Equal(t, gempki.CertTypeUnknown, gempki.DetectCertificateType(cert))
	})
}

func TestDetectCertificateType_RoundTrip(t *testing.T) {
	t.Parallel()
	all := []gempki.CertificateType{
		gempki.CertTypeChQES, gempki.CertTypeChSIG, gempki.CertTypeChENC,
		gempki.CertTypeChENCV, gempki.CertTypeChAUT, gempki.CertTypeChAUTN,
		gempki.CertTypeHpQES, gempki.CertTypeHpAUT, gempki.CertTypeHpENC,
		gempki.CertTypeHciAUT, gempki.CertTypeHciENC, gempki.CertTypeHciOSIG,
		gempki.CertTypeFdTLSS, gempki.CertTypeFdTLSC, gempki.CertTypeFdSIG,
		gempki.CertTypeFdENC, gempki.CertTypeFdAUT, gempki.CertTypeFdOSIG,
		gempki.CertTypeZdTLSS, gempki.CertTypeZdSIG,
		gempki.CertTypeHskSIG, gempki.CertTypeHskENC, gempki.CertTypeGemVER,
	}
	for _, want := range all {
		t.Run(string(want), func(t *testing.T) {
			oid := want.OID()
			require.NotEmpty(t, oid, "every named type must have a registered OID")
			cert := buildTestCert(t, buildOpts{
				policies: []asn1.ObjectIdentifier{oid},
				keyUsage: x509.KeyUsageDigitalSignature,
			})
			assert.Equal(t, want, gempki.DetectCertificateType(cert))
		})
	}
}

func TestCertificateType_DefaultProfile(t *testing.T) {
	t.Parallel()
	type tc struct {
		typed gempki.CertificateType
		want  *gempki.Profile
	}
	cases := []tc{
		{gempki.CertTypeHciAUT, gempki.ProfileSmbAuth},
		{gempki.CertTypeFdSIG, gempki.ProfileIdp},
		// C.FD.AUT is the 1:N case: accepted by both epavau and idp, no
		// default-for. Auto mode warns; user picks.
		{gempki.CertTypeFdAUT, nil},
		// Types with no profile in the slimmed registry.
		{gempki.CertTypeHpQES, nil},
		{gempki.CertTypeFdTLSS, nil},
		{gempki.CertTypeHciENC, nil},
		{gempki.CertTypeChQES, nil},
		{gempki.CertTypeUnknown, nil},
	}
	for _, c := range cases {
		t.Run(string(c.typed), func(t *testing.T) {
			assert.Same(t, c.want, c.typed.DefaultProfile())
		})
	}
}

func TestProfilesForType(t *testing.T) {
	t.Parallel()
	type tc struct {
		typed gempki.CertificateType
		want  []*gempki.Profile // expected, order-insensitive
	}
	cases := []tc{
		{gempki.CertTypeHciAUT, []*gempki.Profile{gempki.ProfileSmbAuth}},
		{gempki.CertTypeFdSIG, []*gempki.Profile{gempki.ProfileIdp}},
		// 1:N — both profiles accept this type.
		{gempki.CertTypeFdAUT, []*gempki.Profile{gempki.ProfileEpaVau, gempki.ProfileIdp}},
		{gempki.CertTypeHpQES, nil},
		{gempki.CertTypeFdTLSS, nil},
		{gempki.CertTypeUnknown, nil},
	}
	for _, c := range cases {
		t.Run(string(c.typed), func(t *testing.T) {
			got := gempki.ProfilesForType(c.typed)
			assert.ElementsMatch(t, c.want, got)
		})
	}
}

func TestCertTypeSpec(t *testing.T) {
	t.Parallel()
	// HCI.AUT — fully populated baseline including SMC-B institution role OIDs.
	hciAUT := gempki.CertTypeHciAUT.Spec()
	assert.NotZero(t, hciAUT.KeyUsage)
	assert.NotEmpty(t, hciAUT.EKU)
	assert.NotEmpty(t, hciAUT.Policies)
	assert.NotEmpty(t, hciAUT.RoleOIDs, "C.HCI.AUT must mandate institution role OIDs")

	// FD.AUT — KeyUsage + Policies, no EKU / role OIDs (Fachdienst certs).
	fdAUT := gempki.CertTypeFdAUT.Spec()
	assert.NotZero(t, fdAUT.KeyUsage)
	assert.Empty(t, fdAUT.EKU)
	assert.NotEmpty(t, fdAUT.Policies)
	assert.Empty(t, fdAUT.RoleOIDs)

	// FD.SIG — same shape as FD.AUT.
	fdSIG := gempki.CertTypeFdSIG.Spec()
	assert.NotZero(t, fdSIG.KeyUsage)
	assert.NotEmpty(t, fdSIG.Policies)

	// HP.QES — contentCommitment + HBA profession role OIDs.
	hpQES := gempki.CertTypeHpQES.Spec()
	assert.NotZero(t, hpQES.KeyUsage)
	assert.NotEmpty(t, hpQES.Policies)
	assert.NotEmpty(t, hpQES.RoleOIDs, "C.HP.QES must mandate HBA profession role OIDs")

	// Unknown returns zero value, not a panic.
	assert.Equal(t, gempki.CertTypeSpec{}, gempki.CertTypeUnknown.Spec())
}
