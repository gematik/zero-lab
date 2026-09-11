package oid

import "encoding/asn1"

// Info is what gemSpec_OID records about an object identifier: the
// reference other gematik documents cite it by, a description, and the
// document that defines it.
type Info struct {
	// Ref is the gemSpec_OID reference name, e.g. `oid_policy_gem_or_cp`.
	Ref string
	// Description is the spec's own wording, kept in German where that is
	// how the table reads.
	Description string
	// Document is the defining document, e.g. `[gemSpec_TSL]`. Empty when
	// the table names none.
	Document string
}

// infos is keyed by the dotted form so lookup needs no OID comparison. Only
// OIDs gempki validates against carry an entry; gempki's own test checks
// every OID a profile or type baseline asserts is here.
var infos = map[string]Info{
	// Tab_PKI_404 — Certificate Policies.
	PolicyHbaCP.String(): {
		Ref:         "oid_policy_hba_cp",
		Description: "Policy HPC QES, SIG, AUT, ENC",
		Document:    "[CP-HPC]",
	},
	PolicyGemOrCP.String(): {
		Ref:         "oid_policy_gem_or_cp",
		Description: "Policy für alle Zertifikate ab Online-Rollout (eGK, SMC, Komponentenzertifikate) außer für das TSL-Signerzertifikat",
		Document:    "[gemRL_TSL_SP_CP]",
	},
	PolicyGemTSLSigner.String(): {
		Ref:         "oid_policy_gem_tsl_signer",
		Description: "Policy für das TSL-Signerzertifikat",
		Document:    "[gemSpec_TSL]",
	},

	// Tab_PKI_403 — the SMC-B institution roles a C.HCI.AUT may assert.
	InstArztpraxis.String():            {Ref: "oid_praxis_arzt", Description: "Betriebsstätte Arzt"},
	InstZahnarztpraxis.String():        {Ref: "oid_zahnarztpraxis", Description: "Zahnarztpraxis"},
	InstPraxisPsychotherapeut.String(): {Ref: "oid_praxis_psychotherapeut", Description: "Praxis Psychotherapeut"},
	InstKrankenhaus.String():           {Ref: "oid_krankenhaus", Description: "Krankenhaus"},
	InstOeffentlicheApo.String():       {Ref: "oid_oeffentliche_apotheke", Description: "Öffentliche Apotheke"},
	InstKrankenhausapotheke.String():   {Ref: "oid_krankenhausapotheke", Description: "Krankenhausapotheke"},
	InstBundeswehrapotheke.String():    {Ref: "oid_bundeswehrapotheke", Description: "Bundeswehrapotheke"},

	// Tab_PKI_405 — the certificate types; the description is the type name
	// gemSpec_PKI uses, which is also gempki.CertificateType's value.
	CertTypeEgkQES.String():   {Ref: "oid_c_ch_qes", Description: "C.CH.QES"},
	CertTypeEgkSIG.String():   {Ref: "oid_c_ch_sig", Description: "C.CH.SIG"},
	CertTypeEgkENC.String():   {Ref: "oid_c_ch_enc", Description: "C.CH.ENC"},
	CertTypeEgkENCV.String():  {Ref: "oid_c_ch_encv", Description: "C.CH.ENCV"},
	CertTypeEgkAUT.String():   {Ref: "oid_c_ch_aut", Description: "C.CH.AUT"},
	CertTypeEgkAUTN.String():  {Ref: "oid_c_ch_autn", Description: "C.CH.AUTN"},
	CertTypeHbaQES.String():   {Ref: "oid_c_hp_qes", Description: "C.HP.QES"},
	CertTypeHbaENC.String():   {Ref: "oid_c_hp_enc", Description: "C.HP.ENC"},
	CertTypeHbaAUT.String():   {Ref: "oid_c_hp_aut", Description: "C.HP.AUT"},
	CertTypeSmcBENC.String():  {Ref: "oid_c_hci_enc", Description: "C.HCI.ENC"},
	CertTypeSmcBAUT.String():  {Ref: "oid_c_hci_aut", Description: "C.HCI.AUT"},
	CertTypeSmcBOSIG.String(): {Ref: "oid_c_hci_osig", Description: "C.HCI.OSIG"},
	CertTypeFdTLSS.String():   {Ref: "oid_c_fd_tls_s", Description: "C.FD.TLS-S"},
	CertTypeFdTLSC.String():   {Ref: "oid_c_fd_tls_c", Description: "C.FD.TLS-C"},
	CertTypeFdSIG.String():    {Ref: "oid_c_fd_sig", Description: "C.FD.SIG"},
	CertTypeFdENC.String():    {Ref: "oid_c_fd_enc", Description: "C.FD.ENC"},
	CertTypeFdAUT.String():    {Ref: "oid_c_fd_aut", Description: "C.FD.AUT"},
	CertTypeFdOSIG.String():   {Ref: "oid_c_fd_osig", Description: "C.FD.OSIG"},
	CertTypeZdTLSS.String():   {Ref: "oid_c_zd_tls_s", Description: "C.ZD.TLS-S"},
	CertTypeZdSIG.String():    {Ref: "oid_c_zd_sig", Description: "C.ZD.SIG"},
	CertTypeHskSIG.String():   {Ref: "oid_c_hsk_sig", Description: "C.HSK.SIG"},
	CertTypeHskENC.String():   {Ref: "oid_c_hsk_enc", Description: "C.HSK.ENC"},
	CertTypeGemVER.String():   {Ref: "oid_c_gem_ver", Description: "C.GEM.VER"},

	// Tab_PKI_406 — technical roles referenced by a profile.
	TechRoleZETAGuard.String(): {Ref: "oid_zeta-guard", Description: "ZETA Guard"},
	TechRoleEpaVAU.String():    {Ref: "oid_epa_vau", Description: "ePA vertrauenswürdige Ausführungsumgebung"},
	TechRoleIDPD.String():      {Ref: "oid_idpd", Description: "IDP-Dienst"},
}

// Lookup returns what gemSpec_OID says about oid, if this package knows
// it. Unknown OIDs are not an error — the tables are large and only the
// OIDs gempki validates against are listed.
func Lookup(oid asn1.ObjectIdentifier) (Info, bool) {
	info, ok := infos[oid.String()]
	return info, ok
}

// Format renders an OID for display: `1.2.276.0.76.4.328 (ZETA Guard)`
// when the name is known, the bare dotted form otherwise.
func Format(oid asn1.ObjectIdentifier) string {
	if info, ok := infos[oid.String()]; ok && info.Description != "" {
		return oid.String() + " (" + info.Description + ")"
	}
	return oid.String()
}
