package gempki

import (
	"encoding/asn1"
	"strings"
)

// OIDInfo is what gemSpec_OID records about an object identifier: the
// reference other gematik documents cite it by, a description, and the
// document that defines it.
type OIDInfo struct {
	// Ref is the gemSpec_OID reference name, e.g. `oid_policy_gem_or_cp`.
	Ref string
	// Description is the spec's own wording, kept in German where that is
	// how the table reads.
	Description string
	// Document is the defining document, e.g. `[gemSpec_TSL]`. Empty when
	// the table names none.
	Document string
}

// oidInfo is keyed by the dotted form so lookup needs no OID comparison.
// Only OIDs this package validates against are listed; the coverage test
// enforces that every OID reachable from a profile or a type spec is here.
var oidInfo = map[string]OIDInfo{
	// Tab_PKI_404 — Certificate Policies.
	OIDPolicyHbaCP.String(): {
		Ref:         "oid_policy_hba_cp",
		Description: "Policy HPC QES, SIG, AUT, ENC",
		Document:    "[CP-HPC]",
	},
	OIDPolicyGemOrCP.String(): {
		Ref:         "oid_policy_gem_or_cp",
		Description: "Policy für alle Zertifikate ab Online-Rollout (eGK, SMC, Komponentenzertifikate) außer für das TSL-Signerzertifikat",
		Document:    "[gemRL_TSL_SP_CP]",
	},
	OIDPolicyGemTSLSigner.String(): {
		Ref:         "oid_policy_gem_tsl_signer",
		Description: "Policy für das TSL-Signerzertifikat",
		Document:    "[gemSpec_TSL]",
	},

	// Tab_PKI_403 — the SMC-B institution roles a C.HCI.AUT may assert.
	OIDInstArztpraxis.String():            {Ref: "oid_praxis_arzt", Description: "Betriebsstätte Arzt"},
	OIDInstZahnarztpraxis.String():        {Ref: "oid_zahnarztpraxis", Description: "Zahnarztpraxis"},
	OIDInstPraxisPsychotherapeut.String(): {Ref: "oid_praxis_psychotherapeut", Description: "Praxis Psychotherapeut"},
	OIDInstKrankenhaus.String():           {Ref: "oid_krankenhaus", Description: "Krankenhaus"},
	OIDInstOeffentlicheApo.String():       {Ref: "oid_oeffentliche_apotheke", Description: "Öffentliche Apotheke"},
	OIDInstKrankenhausapotheke.String():   {Ref: "oid_krankenhausapotheke", Description: "Krankenhausapotheke"},
	OIDInstBundeswehrapotheke.String():    {Ref: "oid_bundeswehrapotheke", Description: "Bundeswehrapotheke"},

	// Tab_PKI_406 — technical roles referenced by a profile.
	OIDTechRoleZETAGuard.String(): {Ref: "oid_zeta-guard", Description: "ZETA Guard"},
	OIDTechRoleEpaVAU.String():    {Ref: "oid_epa_vau", Description: "ePA vertrauenswürdige Ausführungsumgebung"},
	OIDTechRoleIDPD.String():      {Ref: "oid_idpd", Description: "IDP-Dienst"},
}

// The Tab_PKI_405 certificate-type OIDs label themselves: the CertificateType
// value *is* the spec's name for them ("C.FD.AUT"), so seeding from that table
// keeps the two from drifting and covers all 23 without hand-copying.
func init() {
	for t, oid := range certTypeOID {
		key := oid.String()
		if _, taken := oidInfo[key]; taken {
			continue
		}
		oidInfo[key] = OIDInfo{Ref: "oid_" + strings.ToLower(strings.ReplaceAll(string(t), ".", "_")), Description: string(t)}
	}
}

// LookupOID returns what gemSpec_OID says about oid, if this package knows
// it. Unknown OIDs are not an error — the tables are large and only the
// OIDs gempki validates against are listed.
func LookupOID(oid asn1.ObjectIdentifier) (OIDInfo, bool) {
	info, ok := oidInfo[oid.String()]
	return info, ok
}

// FormatOID renders an OID for display: `1.2.276.0.76.4.328 (ZETA Guard)`
// when the name is known, the bare dotted form otherwise.
func FormatOID(oid asn1.ObjectIdentifier) string {
	if info, ok := oidInfo[oid.String()]; ok && info.Description != "" {
		return oid.String() + " (" + info.Description + ")"
	}
	return oid.String()
}
