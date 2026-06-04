package gempki_test

import (
	"encoding/asn1"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
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
		{"Instance.gematik", gempki.OIDInstanceGematik, "1.2.276.0.76.3.1.91"},
		// Tab_PKI_402 — Professions
		{"Prof.Arzt", gempki.OIDProfArzt, "1.2.276.0.76.4.30"},
		{"Prof.Apotheker", gempki.OIDProfApotheker, "1.2.276.0.76.4.32"},
		{"Prof.Psychotherapeut", gempki.OIDProfPsychotherapeut, "1.2.276.0.76.4.45"},
		{"Prof.Notfallsanitaeter", gempki.OIDProfNotfallsanitaeter, "1.2.276.0.76.4.178"},
		{"Prof.PflegerHPC", gempki.OIDProfPflegerHPC, "1.2.276.0.76.4.232"},
		// Tab_PKI_403 — Institutions
		{"Inst.Arztpraxis", gempki.OIDInstArztpraxis, "1.2.276.0.76.4.50"},
		{"Inst.Krankenhaus", gempki.OIDInstKrankenhaus, "1.2.276.0.76.4.53"},
		{"Inst.OeffentlicheApo", gempki.OIDInstOeffentlicheApo, "1.2.276.0.76.4.54"},
		{"Inst.Gematik", gempki.OIDInstGematik, "1.2.276.0.76.4.58"},
		// Tab_PKI_404 — Policies
		{"Policy.HbaCP", gempki.OIDPolicyHbaCP, "1.2.276.0.76.4.145"},
		{"Policy.GemOrCP", gempki.OIDPolicyGemOrCP, "1.2.276.0.76.4.163"},
		// Tab_PKI_405 — Certificate types
		{"CertType.HbaQES", gempki.OIDCertTypeHbaQES, "1.2.276.0.76.4.72"},
		{"CertType.SmcBAUT", gempki.OIDCertTypeSmcBAUT, "1.2.276.0.76.4.77"},
		{"CertType.FdTLSS", gempki.OIDCertTypeFdTLSS, "1.2.276.0.76.4.169"},
		// Tab_PKI_406 — Technical roles
		{"TechRole.IDPD", gempki.OIDTechRoleIDPD, "1.2.276.0.76.4.260"},
		{"TechRole.EpaVAU", gempki.OIDTechRoleEpaVAU, "1.2.276.0.76.4.209"},
		{"TechRole.ERezept", gempki.OIDTechRoleERezept, "1.2.276.0.76.4.259"},
		{"TechRole.ZETAGuard", gempki.OIDTechRoleZETAGuard, "1.2.276.0.76.4.328"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.got.String())
		})
	}
}
