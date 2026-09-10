package gempki_test

import (
	"context"
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
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProfileRegistry(t *testing.T) {
	t.Parallel()
	require.NoError(t, gempki.ValidateProfileRegistry())
	assert.Equal(t, []string{"epa-vau-aut", "idp-sig", "smb-aut", "zeta-asl-aut"}, gempki.ProfileNames())
	assert.Equal(t,
		[]string{"auto", "none", "epa-vau-aut", "idp-sig", "smb-aut", "zeta-asl-aut"},
		gempki.ProfileSelectorValues())
}

func TestLookupProfile(t *testing.T) {
	t.Parallel()
	p, ok := gempki.LookupProfile("ZETA-ASL-AUT")
	require.True(t, ok)
	assert.Same(t, gempki.ProfileZetaASL, p)

	for _, name := range []string{"", "auto", "none", "idp", "epavau", "smbauth", "epa-vau", "zeta-asl"} {
		_, ok := gempki.LookupProfile(name)
		assert.False(t, ok, "%q must not resolve to a profile", name)
	}
}

func TestEffectiveRoleOIDs(t *testing.T) {
	t.Parallel()
	// A profile that declares none inherits the type baseline...
	assert.Equal(t,
		gempki.CertTypeHciAUT.Spec().RoleOIDs,
		gempki.ProfileSmbAut.EffectiveRoleOIDs(gempki.CertTypeHciAUT))

	// ...and one that declares its own replaces it rather than widening it.
	// C.FD.AUT carries no baseline roles, so also assert the replacement is
	// exactly the profile's list and not a concatenation.
	assert.Equal(t,
		[]asn1.ObjectIdentifier{gempki.OIDTechRoleZETAGuard},
		gempki.ProfileZetaASL.EffectiveRoleOIDs(gempki.CertTypeFdAUT))
	assert.Equal(t,
		[]asn1.ObjectIdentifier{gempki.OIDTechRoleZETAGuard},
		gempki.ProfileZetaASL.EffectiveRoleOIDs(gempki.CertTypeHciAUT),
		"a profile's role OIDs replace the type baseline, they do not merge with it")
}

func TestProfileZetaASL_ValidatorRequiresZETARole(t *testing.T) {
	t.Parallel()
	ts := trustStoreOf(t)
	v := gempki.ProfileZetaASL.Validator(ts, gempki.CertTypeFdAUT)
	assert.Equal(t, []asn1.ObjectIdentifier{gempki.OIDTechRoleZETAGuard}, v.RequiredRoleOIDs)
	assert.Equal(t, gempki.RevocationModeHardFail, v.Revocation.Mode)

	check := gempki.CheckRoleOID(nil, v.RequiredRoleOIDs...)
	assert.NoError(t, check(context.Background(), zetaCert(t)),
		"a C.FD.AUT asserting ZETA Guard must satisfy the profile")

	err := check(context.Background(), fdAutCert(t))
	require.Error(t, err, "a C.FD.AUT with no admission extension must not")
	var verr *gempki.ValidationError
	require.ErrorAs(t, err, &verr)
	assert.Equal(t, gempki.ErrCodeRoleOIDMissing, verr.Code)
}

func TestSelectProfileForCert(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		cert       *x509.Certificate
		wantType   gempki.CertificateType
		wantProf   *gempki.Profile
		wantReason gempki.ProfileSelectReason
	}{
		{
			name:       "ZETA C.FD.AUT is claimed by its role",
			cert:       zetaCert(t),
			wantType:   gempki.CertTypeFdAUT,
			wantProf:   gempki.ProfileZetaASL,
			wantReason: gempki.ProfileSelectedByCert,
		},
		{
			name:       "ePA VAU C.FD.AUT is claimed by its own role",
			cert:       epaVauCert(t),
			wantType:   gempki.CertTypeFdAUT,
			wantProf:   gempki.ProfileEpaVau,
			wantReason: gempki.ProfileSelectedByCert,
		},
		{
			// Both C.FD.AUT profiles are role-discriminated, so a C.FD.AUT
			// asserting neither role is not claimed by either. Guessing here
			// would validate an IDP JWKS cert against ePA VAU assertions.
			name:       "C.FD.AUT with no role is claimed by nobody",
			cert:       fdAutCert(t),
			wantType:   gempki.CertTypeFdAUT,
			wantReason: gempki.ProfileSelectAmbiguous,
		},
		{
			name:       "C.FD.AUT with an unrelated role is claimed by nobody",
			cert:       certWith(t, []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdAUT}, gempki.OIDInstKrankenhaus, "Krankenhaus"),
			wantType:   gempki.CertTypeFdAUT,
			wantReason: gempki.ProfileSelectAmbiguous,
		},
		{
			name:       "C.FD.SIG",
			cert:       certWith(t, []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdSIG}, nil, ""),
			wantType:   gempki.CertTypeFdSIG,
			wantProf:   gempki.ProfileIdpSig,
			wantReason: gempki.ProfileSelectedByDefault,
		},
		{
			name:       "a type no profile accepts",
			cert:       certWith(t, []asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdTLSS}, nil, ""),
			wantType:   gempki.CertTypeFdTLSS,
			wantReason: gempki.ProfileSelectNone,
		},
		{
			name:       "an unrecognisable certificate",
			cert:       certWith(t, nil, nil, ""),
			wantType:   gempki.CertTypeUnknown,
			wantReason: gempki.ProfileSelectNone,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := gempki.SelectProfileForCert(c.cert)
			assert.Equal(t, c.wantType, got.Type)
			assert.Same(t, c.wantProf, got.Profile)
			assert.Equal(t, c.wantReason, got.Reason)
			assert.NotEmpty(t, got.Detail, "every selection must say why")
		})
	}
}

func TestSelectProfileForCert_SMCB(t *testing.T) {
	t.Parallel()
	// The one case worth driving from a real fixture rather than a synthetic
	// cert: detection of C.HCI.AUT runs through the admission backstop.
	pki, err := testca.New()
	require.NoError(t, err)
	got := gempki.SelectProfileForCert(pki.EEArzt.Cert)
	assert.Equal(t, gempki.CertTypeHpAUT, got.Type)
	assert.Equal(t, gempki.ProfileSelectNone, got.Reason,
		"HBA C.HP.AUT has no profile; the registry should say so rather than guess")
}

func TestProfilesForCert(t *testing.T) {
	t.Parallel()
	// Both profiles accept the type, only zeta-asl claims the cert.
	assert.Equal(t,
		[]*gempki.Profile{gempki.ProfileEpaVau, gempki.ProfileZetaASL},
		gempki.ProfilesForType(gempki.CertTypeFdAUT))
	assert.Equal(t,
		[]*gempki.Profile{gempki.ProfileZetaASL},
		gempki.ProfilesForCert(zetaCert(t)))
	assert.Equal(t,
		[]*gempki.Profile{gempki.ProfileEpaVau},
		gempki.ProfilesForCert(epaVauCert(t)))
	assert.Empty(t, gempki.ProfilesForCert(fdAutCert(t)),
		"neither C.FD.AUT profile claims a cert with no admission role")
	assert.Nil(t, gempki.ProfilesForCert(nil))
}

func TestFormatOID(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1.2.276.0.76.4.328 (ZETA Guard)", gempki.FormatOID(gempki.OIDTechRoleZETAGuard))
	assert.Equal(t, "1.2.3.4", gempki.FormatOID(asn1.ObjectIdentifier{1, 2, 3, 4}))

	info, ok := gempki.LookupOID(gempki.OIDPolicyGemTSLSigner)
	require.True(t, ok)
	assert.Equal(t, "oid_policy_gem_tsl_signer", info.Ref)
	assert.Equal(t, "[gemSpec_TSL]", info.Document)
}

// TestOIDLabelsCoverValidatedOIDs keeps the label table honest: every OID a
// profile or type baseline actually asserts must render with a name, or
// `profiles describe` degrades to bare dotted numbers.
func TestOIDLabelsCoverValidatedOIDs(t *testing.T) {
	t.Parallel()
	for _, p := range gempki.ProfileRegistry {
		for _, oid := range p.RequiredRoleOIDs {
			_, ok := gempki.LookupOID(oid)
			assert.True(t, ok, "profile %s requires role %s with no label", p.Name, oid)
		}
		for _, t2 := range p.AcceptsTypes {
			for _, oid := range t2.Spec().RoleOIDs {
				_, ok := gempki.LookupOID(oid)
				assert.True(t, ok, "type %s requires role %s with no label", t2, oid)
			}
		}
	}
}

// --- helpers ---------------------------------------------------------------

func trustStoreOf(t *testing.T) *gempki.TrustStore {
	t.Helper()
	pki, err := testca.New()
	require.NoError(t, err)
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA1.Cert})
	require.NoError(t, err)
	return ts
}

func zetaCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return certWith(t,
		[]asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdAUT},
		gempki.OIDTechRoleZETAGuard, "ZETA Guard")
}

func epaVauCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return certWith(t,
		[]asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdAUT},
		gempki.OIDTechRoleEpaVAU, "ePA VAU")
}

func fdAutCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return certWith(t,
		[]asn1.ObjectIdentifier{gempki.OIDPolicyGemOrCP, gempki.OIDCertTypeFdAUT}, nil, "")
}

func toX509OIDs(t *testing.T, oids []asn1.ObjectIdentifier) []x509.OID {
	t.Helper()
	out := make([]x509.OID, 0, len(oids))
	for _, oid := range oids {
		ints := make([]uint64, len(oid))
		for i, v := range oid {
			ints[i] = uint64(v)
		}
		converted, err := x509.OIDFromInts(ints)
		require.NoError(t, err)
		out = append(out, converted)
	}
	return out
}

// certWith mints a self-signed EE carrying the given certificate policies
// and, when professionOID is set, an admission extension asserting it.
func certWith(t *testing.T, policies []asn1.ObjectIdentifier, professionOID asn1.ObjectIdentifier, professionItem string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svc.example.de"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Policies, not the deprecated PolicyIdentifiers: CreateCertificate
		// silently drops the latter, so the extension would never be written.
		Policies: toX509OIDs(t, policies),
	}
	if professionOID != nil {
		ext, err := testca.AdmissionExtension(professionItem, professionOID, "80276001081234567890")
		require.NoError(t, err)
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
