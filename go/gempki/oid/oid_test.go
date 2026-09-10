package oid_test

import (
	"encoding/asn1"
	"testing"

	"github.com/gematik/zero-lab/go/gempki/oid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDConstants_MatchSpec spot-checks a sample of the spec-derived OIDs
// to guard against typos during the data port from gemSpec_OID. It does not
// re-validate every constant — that would just shuffle data between two
// places — but it covers each Tab_PKI_* table.
func TestOIDConstants_MatchSpec(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		got  asn1.ObjectIdentifier
		want string
	}{
		// Tab_PKI_401 — Instance
		{"Instance.gematik", oid.InstanceGematik, "1.2.276.0.76.3.1.91"},
		// Tab_PKI_402 — Professions
		{"Prof.Arzt", oid.ProfArzt, "1.2.276.0.76.4.30"},
		{"Prof.Apotheker", oid.ProfApotheker, "1.2.276.0.76.4.32"},
		{"Prof.Psychotherapeut", oid.ProfPsychotherapeut, "1.2.276.0.76.4.45"},
		{"Prof.Notfallsanitaeter", oid.ProfNotfallsanitaeter, "1.2.276.0.76.4.178"},
		{"Prof.PflegerHPC", oid.ProfPflegerHPC, "1.2.276.0.76.4.232"},
		// Tab_PKI_403 — Institutions
		{"Inst.Arztpraxis", oid.InstArztpraxis, "1.2.276.0.76.4.50"},
		{"Inst.Krankenhaus", oid.InstKrankenhaus, "1.2.276.0.76.4.53"},
		{"Inst.OeffentlicheApo", oid.InstOeffentlicheApo, "1.2.276.0.76.4.54"},
		{"Inst.Gematik", oid.InstGematik, "1.2.276.0.76.4.58"},
		// Tab_PKI_404 — Policies
		{"Policy.HbaCP", oid.PolicyHbaCP, "1.2.276.0.76.4.145"},
		{"Policy.GemOrCP", oid.PolicyGemOrCP, "1.2.276.0.76.4.163"},
		// Tab_PKI_405 — Certificate types
		{"CertType.HbaQES", oid.CertTypeHbaQES, "1.2.276.0.76.4.72"},
		{"CertType.SmcBAUT", oid.CertTypeSmcBAUT, "1.2.276.0.76.4.77"},
		{"CertType.FdTLSS", oid.CertTypeFdTLSS, "1.2.276.0.76.4.169"},
		// Tab_PKI_406 — Technical roles
		{"TechRole.IDPD", oid.TechRoleIDPD, "1.2.276.0.76.4.260"},
		{"TechRole.EpaVAU", oid.TechRoleEpaVAU, "1.2.276.0.76.4.209"},
		{"TechRole.ERezept", oid.TechRoleERezept, "1.2.276.0.76.4.259"},
		{"TechRole.ZETAGuard", oid.TechRoleZETAGuard, "1.2.276.0.76.4.328"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.got.String())
		})
	}
}

func TestTables_CoverTheirConstants(t *testing.T) {
	t.Parallel()
	for name, table := range map[string][]asn1.ObjectIdentifier{"Professions": oid.Professions, "Institutions": oid.Institutions} {
		seen := map[string]bool{}
		for _, o := range table {
			assert.False(t, seen[o.String()], "%s lists %s twice", name, o)
			seen[o.String()] = true
		}
		assert.Greater(t, len(table), 40, "%s looks truncated", name)
	}
	assert.Contains(t, oid.Institutions, oid.InstArztpraxis)
	assert.Contains(t, oid.Professions, oid.ProfArzt)
	assert.NotContains(t, oid.Professions, oid.ProfVersicherter, "the eGK marker is not a profession")
}

func TestFormat(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1.2.276.0.76.4.328 (ZETA Guard)", oid.Format(oid.TechRoleZETAGuard))
	assert.Equal(t, "1.2.276.0.76.4.155 (C.FD.AUT)", oid.Format(oid.CertTypeFdAUT))
	assert.Equal(t, "1.2.3.4", oid.Format(asn1.ObjectIdentifier{1, 2, 3, 4}))

	info, ok := oid.Lookup(oid.PolicyGemTSLSigner)
	require.True(t, ok)
	assert.Equal(t, "oid_policy_gem_tsl_signer", info.Ref)
	assert.Equal(t, "[gemSpec_TSL]", info.Document)
}
