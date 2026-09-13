package gempki

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/gematik/zero-lab/go/gempki/oid"
)

// CertificateType is a gemSpec_PKI Tab_PKI_405 certificate-type label
// (e.g. "C.HCI.AUT" for an SMC-B authentication cert). The empty value
// [CertTypeUnknown] means the cert isn't recognised by [DetectCertificateType].
//
// The names match gemSpec_PKI exactly so they can be quoted back to users
// without translation.
type CertificateType string

const (
	// CertTypeUnknown is returned when [DetectCertificateType] can't
	// classify the cert. It is the zero value so callers can compare with
	// `== ""` if they don't want to import the constant.
	CertTypeUnknown CertificateType = ""

	// eGK (Versichertenkarte / electronic health card)
	CertTypeChQES  CertificateType = "C.CH.QES"
	CertTypeChSIG  CertificateType = "C.CH.SIG"
	CertTypeChENC  CertificateType = "C.CH.ENC"
	CertTypeChENCV CertificateType = "C.CH.ENCV"
	CertTypeChAUT  CertificateType = "C.CH.AUT"
	CertTypeChAUTN CertificateType = "C.CH.AUTN"

	// HBA (Heilberufsausweis / professional ID card)
	CertTypeHpQES CertificateType = "C.HP.QES"
	CertTypeHpAUT CertificateType = "C.HP.AUT"
	CertTypeHpENC CertificateType = "C.HP.ENC"

	// SMC-B (Security Module Card — Institution)
	CertTypeHciAUT  CertificateType = "C.HCI.AUT"
	CertTypeHciENC  CertificateType = "C.HCI.ENC"
	CertTypeHciOSIG CertificateType = "C.HCI.OSIG"

	// Fachdienst
	CertTypeFdTLSS CertificateType = "C.FD.TLS-S"
	CertTypeFdTLSC CertificateType = "C.FD.TLS-C"
	CertTypeFdSIG  CertificateType = "C.FD.SIG"
	CertTypeFdENC  CertificateType = "C.FD.ENC"
	CertTypeFdAUT  CertificateType = "C.FD.AUT"
	CertTypeFdOSIG CertificateType = "C.FD.OSIG"

	// Zentraler Dienst
	CertTypeZdTLSS CertificateType = "C.ZD.TLS-S"
	CertTypeZdSIG  CertificateType = "C.ZD.SIG"

	// HSK / GemVER
	CertTypeHskSIG CertificateType = "C.HSK.SIG"
	CertTypeHskENC CertificateType = "C.HSK.ENC"
	CertTypeGemVER CertificateType = "C.GEM.VER"
)

// CertTypeSpec is the gemSpec_PKI-mandated validation baseline for a cert
// type — what every cert of this type must satisfy regardless of which
// [Profile] is enforcing it. A [Profile] layers revocation-mode and other
// use-case-specific overrides on top of this baseline; see
// [Profile.Validator].
//
// Zero fields mean "no requirement at this layer":
//   - KeyUsage == 0   → no KeyUsage check from the type spec
//   - len(EKU) == 0   → no ExtKeyUsage check from the type spec
//   - len(Policies)   → no required CertificatePolicies
//   - len(RoleOIDs)   → no profession/institution role enforcement
type CertTypeSpec struct {
	KeyUsage x509.KeyUsage
	EKU      []x509.ExtKeyUsage
	Policies []asn1.ObjectIdentifier
	RoleOIDs []asn1.ObjectIdentifier
}

// egkInsurantRoleOIDs is the one profession OID every eGK certificate
// asserts. Unlike the HBA and SMC-B tables it is not a choice: an eGK
// names an insurant or it is not an eGK.
var egkInsurantRoleOIDs = []asn1.ObjectIdentifier{oid.ProfVersicherter}

// hskRoleOIDs is the technical role a Highspeed-Konnektor certificate
// carries in its Admission extension (Tab_PKI_284/285).
var hskRoleOIDs = []asn1.ObjectIdentifier{oid.TechRoleHSK}

// certTypeSpec is the per-type baseline behind [CertificateType.Spec],
// transcribed from the X.509 profile tables of gemSpec_PKI (Tab_PKI_232–297,
// one per type) with the ECDSA branch of each — the TI issues no RSA cards
// any more, and an RSA baseline (keyEncipherment for ENC, keyEncipherment
// beside digitalSignature for AUT) would not fit the checks' "every bit must
// be set" reading anyway.
//
// Every value is a floor, not an equality: [CheckKeyUsage] requires the
// listed bits, [CheckHasAnyExtKeyUsage] one of the listed purposes,
// [CheckCertificatePolicies] every listed policy, [CheckRoleOID] one of the
// listed roles. Optional entries of a profile (C.CH.AUT's clientAuth, the
// TSP-specific policy OIDs, the ETSI QSCD policy on C.HP.QES) are therefore
// left out. Role lists are the whole spec tables — every institution of
// Tab_PKI_403 holds an SMC-B, every profession of Tab_PKI_402 an HBA — so
// detection ([DetectCertificateType], which uses the same tables) and
// validation cannot disagree about a certificate. Fachdienst types carry no
// baseline role: the technical role is what a [Profile] discriminates on.
var certTypeSpec = map[CertificateType]CertTypeSpec{
	// eGK — Tab_PKI_232–236, 297. gematik's umbrella policy plus the type.
	CertTypeChQES: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkQES},
		RoleOIDs: egkInsurantRoleOIDs,
	},
	CertTypeChSIG: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkSIG},
		RoleOIDs: egkInsurantRoleOIDs,
	},
	CertTypeChENC: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkENC},
		RoleOIDs: egkInsurantRoleOIDs,
	},
	CertTypeChENCV: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkENCV},
		RoleOIDs: egkInsurantRoleOIDs,
	},
	// C.CH.AUT may carry clientAuth; C.CH.AUTN — the pseudonymous credential
	// that opens TLS sessions in which the holder must stay unidentified —
	// must.
	CertTypeChAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkAUT},
		RoleOIDs: egkInsurantRoleOIDs,
	},
	CertTypeChAUTN: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeEgkAUTN},
		RoleOIDs: egkInsurantRoleOIDs,
	},

	// HBA — Tab_PKI_268–270. The HBA policy, not gematik's umbrella one.
	CertTypeHpQES: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyHbaCP, oid.CertTypeHbaQES},
		RoleOIDs: oid.Professions,
	},
	CertTypeHpAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
		Policies: []asn1.ObjectIdentifier{oid.PolicyHbaCP, oid.CertTypeHbaAUT},
		RoleOIDs: oid.Professions,
	},
	CertTypeHpENC: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		Policies: []asn1.ObjectIdentifier{oid.PolicyHbaCP, oid.CertTypeHbaENC},
		RoleOIDs: oid.Professions,
	},

	// SMC-B — Tab_PKI_238–240.
	CertTypeHciAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeSmcBAUT},
		RoleOIDs: oid.Institutions,
	},
	CertTypeHciENC: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeSmcBENC},
		RoleOIDs: oid.Institutions,
	},
	CertTypeHciOSIG: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeSmcBOSIG},
		RoleOIDs: oid.Institutions,
	},

	// Fachdienst — Tab_PKI_241–246.
	CertTypeFdAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdAUT},
	},
	CertTypeFdSIG: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdSIG},
	},
	CertTypeFdENC: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdENC},
	},
	CertTypeFdOSIG: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdOSIG},
	},
	CertTypeFdTLSS: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdTLSS},
	},
	CertTypeFdTLSC: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeFdTLSC},
	},

	// Zentrale Dienste — Tab_PKI_247, 296.
	CertTypeZdTLSS: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeZdTLSS},
	},
	CertTypeZdSIG: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeZdSIG},
	},

	// Highspeed-Konnektor — Tab_PKI_284/285 — and gematik's verification
	// certificate (Tab_PKI_300), which asserts no key usage at all.
	CertTypeHskSIG: {
		KeyUsage: x509.KeyUsageContentCommitment,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeHskSIG},
		RoleOIDs: hskRoleOIDs,
	},
	CertTypeHskENC: {
		KeyUsage: x509.KeyUsageKeyAgreement,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeHskENC},
		RoleOIDs: hskRoleOIDs,
	},
	CertTypeGemVER: {
		Policies: []asn1.ObjectIdentifier{oid.PolicyGemOrCP, oid.CertTypeGemVER},
	},
}

// Spec returns the gemSpec_PKI-mandated baseline rules for this type. The
// zero [CertTypeSpec] is returned for [CertTypeUnknown] or for any type
// that has no populated baseline yet.
func (t CertificateType) Spec() CertTypeSpec { return certTypeSpec[t] }

// certTypePairs is the Tab_PKI_405 type ↔ OID table; both lookup maps
// derive from it so they cannot disagree.
var certTypePairs = []struct {
	t   CertificateType
	oid asn1.ObjectIdentifier
}{
	{CertTypeChQES, oid.CertTypeEgkQES},
	{CertTypeChSIG, oid.CertTypeEgkSIG},
	{CertTypeChENC, oid.CertTypeEgkENC},
	{CertTypeChENCV, oid.CertTypeEgkENCV},
	{CertTypeChAUT, oid.CertTypeEgkAUT},
	{CertTypeChAUTN, oid.CertTypeEgkAUTN},
	{CertTypeHpQES, oid.CertTypeHbaQES},
	{CertTypeHpAUT, oid.CertTypeHbaAUT},
	{CertTypeHpENC, oid.CertTypeHbaENC},
	{CertTypeHciAUT, oid.CertTypeSmcBAUT},
	{CertTypeHciENC, oid.CertTypeSmcBENC},
	{CertTypeHciOSIG, oid.CertTypeSmcBOSIG},
	{CertTypeFdTLSS, oid.CertTypeFdTLSS},
	{CertTypeFdTLSC, oid.CertTypeFdTLSC},
	{CertTypeFdSIG, oid.CertTypeFdSIG},
	{CertTypeFdENC, oid.CertTypeFdENC},
	{CertTypeFdAUT, oid.CertTypeFdAUT},
	{CertTypeFdOSIG, oid.CertTypeFdOSIG},
	{CertTypeZdTLSS, oid.CertTypeZdTLSS},
	{CertTypeZdSIG, oid.CertTypeZdSIG},
	{CertTypeHskSIG, oid.CertTypeHskSIG},
	{CertTypeHskENC, oid.CertTypeHskENC},
	{CertTypeGemVER, oid.CertTypeGemVER},
}

var (
	certTypeByOID = map[string]CertificateType{}
	certTypeOID   = map[CertificateType]asn1.ObjectIdentifier{}
)

func init() {
	for _, p := range certTypePairs {
		certTypeByOID[p.oid.String()] = p.t
		certTypeOID[p.t] = p.oid
	}
}

// OID returns the Tab_PKI_405 object identifier for this type. Returns an
// empty OID for [CertTypeUnknown] or any type not registered in the map.
func (t CertificateType) OID() asn1.ObjectIdentifier {
	return certTypeOID[t]
}
