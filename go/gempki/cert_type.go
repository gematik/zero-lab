package gempki

import (
	"crypto/x509"
	"encoding/asn1"
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

// smcbInstitutionRoleOIDs are the institution OIDs Tab_PKI_403 accepts on a
// C.HCI.AUT cert. Carried by the type spec, not by an individual profile —
// every C.HCI.AUT cert is expected to assert one of these.
var smcbInstitutionRoleOIDs = []asn1.ObjectIdentifier{
	OIDInstArztpraxis,
	OIDInstZahnarztpraxis,
	OIDInstPraxisPsychotherapeut,
	OIDInstKrankenhaus,
	OIDInstOeffentlicheApo,
	OIDInstKrankenhausapotheke,
	OIDInstBundeswehrapotheke,
}

// hbaQESRoleOIDs are the HBA profession OIDs Tab_PKI_402 accepts on a
// C.HP.QES cert. Carried by the type spec; no profile in the current set
// enforces it directly, but a future QES validator can layer on top of the
// type baseline without re-declaring this list.
var hbaQESRoleOIDs = []asn1.ObjectIdentifier{
	OIDProfArzt,
	OIDProfZahnarzt,
	OIDProfApotheker,
	OIDProfPsychotherapeut,
	OIDProfPsPsychotherapeut,
	OIDProfKuJPsychotherapeut,
}

// certTypeSpec is the per-type baseline lookup used by [CertificateType.Spec].
// Entries populated for the types currently consumed by a profile (HCI.AUT,
// FD.AUT, FD.SIG, HP.QES) plus the TLS family (TLS-S, TLS-C, ZD.TLS-S) for
// documentation. The remaining 16 entries are empty placeholders that still
// signal "known type" to callers; populate them when a real consumer needs
// the baseline.
var certTypeSpec = map[CertificateType]CertTypeSpec{
	CertTypeHciAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeSmcBAUT},
		RoleOIDs: smcbInstitutionRoleOIDs,
	},
	CertTypeHciENC:  {},
	CertTypeHciOSIG: {},

	CertTypeHpQES: {
		KeyUsage: x509.KeyUsageContentCommitment,
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDPolicyHbaCP, OIDCertTypeHbaQES},
		RoleOIDs: hbaQESRoleOIDs,
	},
	CertTypeHpAUT: {},
	CertTypeHpENC: {},

	CertTypeFdAUT: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeFdAUT},
	},
	CertTypeFdSIG: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeFdSIG},
	},
	CertTypeFdTLSS: {
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeFdTLSS},
	},
	CertTypeFdTLSC: {
		KeyUsage: x509.KeyUsageDigitalSignature,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeFdTLSC},
	},
	CertTypeFdENC:  {},
	CertTypeFdOSIG: {},

	CertTypeZdTLSS: {
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		Policies: []asn1.ObjectIdentifier{OIDPolicyGemOrCP, OIDCertTypeZdTLSS},
	},
	CertTypeZdSIG: {},

	CertTypeChQES:  {},
	CertTypeChSIG:  {},
	CertTypeChENC:  {},
	CertTypeChENCV: {},
	CertTypeChAUT:  {},
	CertTypeChAUTN: {},

	CertTypeHskSIG: {},
	CertTypeHskENC: {},
	CertTypeGemVER: {},
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
	{CertTypeChQES, OIDCertTypeEgkQES},
	{CertTypeChSIG, OIDCertTypeEgkSIG},
	{CertTypeChENC, OIDCertTypeEgkENC},
	{CertTypeChENCV, OIDCertTypeEgkENCV},
	{CertTypeChAUT, OIDCertTypeEgkAUT},
	{CertTypeChAUTN, OIDCertTypeEgkAUTN},
	{CertTypeHpQES, OIDCertTypeHbaQES},
	{CertTypeHpAUT, OIDCertTypeHbaAUT},
	{CertTypeHpENC, OIDCertTypeHbaENC},
	{CertTypeHciAUT, OIDCertTypeSmcBAUT},
	{CertTypeHciENC, OIDCertTypeSmcBENC},
	{CertTypeHciOSIG, OIDCertTypeSmcBOSIG},
	{CertTypeFdTLSS, OIDCertTypeFdTLSS},
	{CertTypeFdTLSC, OIDCertTypeFdTLSC},
	{CertTypeFdSIG, OIDCertTypeFdSIG},
	{CertTypeFdENC, OIDCertTypeFdENC},
	{CertTypeFdAUT, OIDCertTypeFdAUT},
	{CertTypeFdOSIG, OIDCertTypeFdOSIG},
	{CertTypeZdTLSS, OIDCertTypeZdTLSS},
	{CertTypeZdSIG, OIDCertTypeZdSIG},
	{CertTypeHskSIG, OIDCertTypeHskSIG},
	{CertTypeHskENC, OIDCertTypeHskENC},
	{CertTypeGemVER, OIDCertTypeGemVER},
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
