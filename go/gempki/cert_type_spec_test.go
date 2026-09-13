package gempki_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The baselines are a transcription of gemSpec_PKI's profile tables; this
// pins the transcription so a change is a deliberate one.
func TestCertTypeSpec_MatchesGemSpecPKI(t *testing.T) {
	t.Parallel()
	egk := []asn1.ObjectIdentifier{oid.ProfVersicherter}
	ds, cc, ka := x509.KeyUsageDigitalSignature, x509.KeyUsageContentCommitment, x509.KeyUsageKeyAgreement
	client, server, mail := x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageEmailProtection
	gem := func(typ asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
		return []asn1.ObjectIdentifier{oid.PolicyGemOrCP, typ}
	}
	hba := func(typ asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
		return []asn1.ObjectIdentifier{oid.PolicyHbaCP, typ}
	}

	want := map[gempki.CertificateType]gempki.CertTypeSpec{
		gempki.CertTypeChQES:   {KeyUsage: cc, Policies: gem(oid.CertTypeEgkQES), RoleOIDs: egk},
		gempki.CertTypeChSIG:   {KeyUsage: cc, Policies: gem(oid.CertTypeEgkSIG), RoleOIDs: egk},
		gempki.CertTypeChENC:   {KeyUsage: ka, Policies: gem(oid.CertTypeEgkENC), RoleOIDs: egk},
		gempki.CertTypeChENCV:  {KeyUsage: ka, Policies: gem(oid.CertTypeEgkENCV), RoleOIDs: egk},
		gempki.CertTypeChAUT:   {KeyUsage: ds, Policies: gem(oid.CertTypeEgkAUT), RoleOIDs: egk},
		gempki.CertTypeChAUTN:  {KeyUsage: ds, EKU: []x509.ExtKeyUsage{client}, Policies: gem(oid.CertTypeEgkAUTN), RoleOIDs: egk},
		gempki.CertTypeHpQES:   {KeyUsage: cc, Policies: hba(oid.CertTypeHbaQES), RoleOIDs: oid.Professions},
		gempki.CertTypeHpAUT:   {KeyUsage: ds | ka, EKU: []x509.ExtKeyUsage{client, mail}, Policies: hba(oid.CertTypeHbaAUT), RoleOIDs: oid.Professions},
		gempki.CertTypeHpENC:   {KeyUsage: ka, Policies: hba(oid.CertTypeHbaENC), RoleOIDs: oid.Professions},
		gempki.CertTypeHciAUT:  {KeyUsage: ds, EKU: []x509.ExtKeyUsage{client}, Policies: gem(oid.CertTypeSmcBAUT), RoleOIDs: oid.Institutions},
		gempki.CertTypeHciENC:  {KeyUsage: ka, Policies: gem(oid.CertTypeSmcBENC), RoleOIDs: oid.Institutions},
		gempki.CertTypeHciOSIG: {KeyUsage: cc, Policies: gem(oid.CertTypeSmcBOSIG), RoleOIDs: oid.Institutions},
		gempki.CertTypeFdAUT:   {KeyUsage: ds, Policies: gem(oid.CertTypeFdAUT)},
		gempki.CertTypeFdSIG:   {KeyUsage: ds, Policies: gem(oid.CertTypeFdSIG)},
		gempki.CertTypeFdENC:   {KeyUsage: ka, Policies: gem(oid.CertTypeFdENC)},
		gempki.CertTypeFdOSIG:  {KeyUsage: cc, Policies: gem(oid.CertTypeFdOSIG)},
		gempki.CertTypeFdTLSS:  {KeyUsage: ds, EKU: []x509.ExtKeyUsage{server}, Policies: gem(oid.CertTypeFdTLSS)},
		gempki.CertTypeFdTLSC:  {KeyUsage: ds, EKU: []x509.ExtKeyUsage{client}, Policies: gem(oid.CertTypeFdTLSC)},
		gempki.CertTypeZdTLSS:  {KeyUsage: ds, EKU: []x509.ExtKeyUsage{server}, Policies: gem(oid.CertTypeZdTLSS)},
		gempki.CertTypeZdSIG:   {KeyUsage: cc, Policies: gem(oid.CertTypeZdSIG)},
		gempki.CertTypeHskSIG:  {KeyUsage: cc, EKU: []x509.ExtKeyUsage{client, server}, Policies: gem(oid.CertTypeHskSIG), RoleOIDs: []asn1.ObjectIdentifier{oid.TechRoleHSK}},
		gempki.CertTypeHskENC:  {KeyUsage: ka, EKU: []x509.ExtKeyUsage{client, server}, Policies: gem(oid.CertTypeHskENC), RoleOIDs: []asn1.ObjectIdentifier{oid.TechRoleHSK}},
		gempki.CertTypeGemVER:  {Policies: gem(oid.CertTypeGemVER)},
	}
	for typ, spec := range want {
		assert.Equal(t, spec, typ.Spec(), string(typ))
	}
	assert.Len(t, want, 23, "every Tab_PKI_405 type gempki knows has a baseline")
}

// A certificate minted to a type's own baseline is detected as that type and
// passes every check the baseline feeds — for each type, with the first role
// of its list where it has one.
func TestCertTypeSpec_RoundTrip(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)

	for _, typ := range knownTypes() {
		spec := typ.Spec()
		t.Run(string(typ), func(t *testing.T) {
			opts := testca.CertOptions{
				KeyUsage:            spec.KeyUsage,
				ExtKeyUsage:         spec.EKU,
				CertificatePolicies: spec.Policies,
			}
			if len(spec.RoleOIDs) > 0 {
				ext, err := testca.AdmissionExtension("role", spec.RoleOIDs[0], "1-test")
				require.NoError(t, err)
				opts.ExtraExtensions = []pkix.Extension{ext}
			}
			cert := customEE(t, pki, opts)

			assert.Equal(t, typ, gempki.DetectCertificateType(cert))
			ctx := context.Background()
			assert.NoError(t, gempki.CheckKeyUsage(spec.KeyUsage)(ctx, cert))
			if len(spec.EKU) > 0 {
				assert.NoError(t, gempki.CheckHasAnyExtKeyUsage(spec.EKU...)(ctx, cert))
			}
			assert.NoError(t, gempki.CheckCertificatePolicies(spec.Policies...)(ctx, cert))
			assert.NoError(t, gempki.CheckRoleOID(spec.RoleOIDs...)(ctx, cert))
		})
	}
}

// Detection and validation read the same tables: an institution or
// profession the old short lists left out is accepted end to end.
func TestCertTypeSpec_RoleListsAreTheSpecTables(t *testing.T) {
	t.Parallel()
	pki, err := testca.New()
	require.NoError(t, err)
	ctx := context.Background()

	for _, tc := range []struct {
		typ  gempki.CertificateType
		role asn1.ObjectIdentifier
	}{
		{gempki.CertTypeHciAUT, oid.InstKostentraeger},
		{gempki.CertTypeHciAUT, oid.InstKIMAnbieter},
		{gempki.CertTypeHpQES, oid.ProfHebammeHPC},
		{gempki.CertTypeHpQES, oid.ProfNotfallsanitaeter},
	} {
		t.Run(string(tc.typ)+"/"+tc.role.String(), func(t *testing.T) {
			spec := tc.typ.Spec()
			ext, err := testca.AdmissionExtension("role", tc.role, "1-test")
			require.NoError(t, err)
			cert := customEE(t, pki, testca.CertOptions{
				KeyUsage:            spec.KeyUsage,
				ExtKeyUsage:         spec.EKU,
				CertificatePolicies: spec.Policies,
				ExtraExtensions:     []pkix.Extension{ext},
			})
			assert.Equal(t, tc.typ, gempki.DetectCertificateType(cert))
			assert.NoError(t, gempki.CheckRoleOID(spec.RoleOIDs...)(ctx, cert))
		})
	}
}

func knownTypes() []gempki.CertificateType {
	return []gempki.CertificateType{
		gempki.CertTypeChQES, gempki.CertTypeChSIG, gempki.CertTypeChENC, gempki.CertTypeChENCV, gempki.CertTypeChAUT, gempki.CertTypeChAUTN,
		gempki.CertTypeHpQES, gempki.CertTypeHpAUT, gempki.CertTypeHpENC,
		gempki.CertTypeHciAUT, gempki.CertTypeHciENC, gempki.CertTypeHciOSIG,
		gempki.CertTypeFdAUT, gempki.CertTypeFdSIG, gempki.CertTypeFdENC, gempki.CertTypeFdOSIG, gempki.CertTypeFdTLSS, gempki.CertTypeFdTLSC,
		gempki.CertTypeZdTLSS, gempki.CertTypeZdSIG,
		gempki.CertTypeHskSIG, gempki.CertTypeHskENC, gempki.CertTypeGemVER,
	}
}
