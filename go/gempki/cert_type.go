package gempki

import (
	"crypto/x509"
	"encoding/asn1"
	"slices"
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

// certTypeByOID is the Tab_PKI_405 OID → name lookup used by the phase-1
// CertificatePolicies scan. Keyed by OID `.String()` for cheap lookup.
var certTypeByOID = map[string]CertificateType{
	OIDCertTypeEgkQES.String():  CertTypeChQES,
	OIDCertTypeEgkSIG.String():  CertTypeChSIG,
	OIDCertTypeEgkENC.String():  CertTypeChENC,
	OIDCertTypeEgkENCV.String(): CertTypeChENCV,
	OIDCertTypeEgkAUT.String():  CertTypeChAUT,
	OIDCertTypeEgkAUTN.String(): CertTypeChAUTN,

	OIDCertTypeHbaQES.String(): CertTypeHpQES,
	OIDCertTypeHbaAUT.String(): CertTypeHpAUT,
	OIDCertTypeHbaENC.String(): CertTypeHpENC,

	OIDCertTypeSmcBAUT.String():  CertTypeHciAUT,
	OIDCertTypeSmcBENC.String():  CertTypeHciENC,
	OIDCertTypeSmcBOSIG.String(): CertTypeHciOSIG,

	OIDCertTypeFdTLSS.String(): CertTypeFdTLSS,
	OIDCertTypeFdTLSC.String(): CertTypeFdTLSC,
	OIDCertTypeFdSIG.String():  CertTypeFdSIG,
	OIDCertTypeFdENC.String():  CertTypeFdENC,
	OIDCertTypeFdAUT.String():  CertTypeFdAUT,
	OIDCertTypeFdOSIG.String(): CertTypeFdOSIG,

	OIDCertTypeZdTLSS.String(): CertTypeZdTLSS,
	OIDCertTypeZdSIG.String():  CertTypeZdSIG,

	OIDCertTypeHskSIG.String(): CertTypeHskSIG,
	OIDCertTypeHskENC.String(): CertTypeHskENC,
	OIDCertTypeGemVER.String(): CertTypeGemVER,
}

// certTypeOID is the reverse map: name → Tab_PKI_405 OID. Populated by an
// inversion loop in the file-local init (no global init() function — see
// the var-init below).
var certTypeOID = func() map[CertificateType]asn1.ObjectIdentifier {
	type pair struct {
		oid asn1.ObjectIdentifier
		t   CertificateType
	}
	pairs := []pair{
		{OIDCertTypeEgkQES, CertTypeChQES},
		{OIDCertTypeEgkSIG, CertTypeChSIG},
		{OIDCertTypeEgkENC, CertTypeChENC},
		{OIDCertTypeEgkENCV, CertTypeChENCV},
		{OIDCertTypeEgkAUT, CertTypeChAUT},
		{OIDCertTypeEgkAUTN, CertTypeChAUTN},
		{OIDCertTypeHbaQES, CertTypeHpQES},
		{OIDCertTypeHbaAUT, CertTypeHpAUT},
		{OIDCertTypeHbaENC, CertTypeHpENC},
		{OIDCertTypeSmcBAUT, CertTypeHciAUT},
		{OIDCertTypeSmcBENC, CertTypeHciENC},
		{OIDCertTypeSmcBOSIG, CertTypeHciOSIG},
		{OIDCertTypeFdTLSS, CertTypeFdTLSS},
		{OIDCertTypeFdTLSC, CertTypeFdTLSC},
		{OIDCertTypeFdSIG, CertTypeFdSIG},
		{OIDCertTypeFdENC, CertTypeFdENC},
		{OIDCertTypeFdAUT, CertTypeFdAUT},
		{OIDCertTypeFdOSIG, CertTypeFdOSIG},
		{OIDCertTypeZdTLSS, CertTypeZdTLSS},
		{OIDCertTypeZdSIG, CertTypeZdSIG},
		{OIDCertTypeHskSIG, CertTypeHskSIG},
		{OIDCertTypeHskENC, CertTypeHskENC},
		{OIDCertTypeGemVER, CertTypeGemVER},
	}
	m := make(map[CertificateType]asn1.ObjectIdentifier, len(pairs))
	for _, p := range pairs {
		m[p.t] = p.oid
	}
	return m
}()

// OID returns the Tab_PKI_405 object identifier for this type. Returns an
// empty OID for [CertTypeUnknown] or any type not registered in the map.
func (t CertificateType) OID() asn1.ObjectIdentifier {
	return certTypeOID[t]
}

// DefaultProfile returns the profile that auto-mode should pick for this
// type, or nil if no profile in [ProfileRegistry] lists t in its
// `DefaultFor`. A nil result means one of:
//   - no profile accepts this type at all → callers should warn
//     [WarnProfileNotDetected];
//   - multiple profiles accept this type but none claims default ownership
//     → callers should warn [WarnProfileAmbiguous] and ask the user to
//     pick via [ProfilesForType].
//
// Callers can distinguish the two with `len(ProfilesForType(t))`.
func (t CertificateType) DefaultProfile() *Profile {
	for _, p := range ProfileRegistry {
		if slices.Contains(p.DefaultFor, t) {
			return p
		}
	}
	return nil
}

// ProfilesForType returns every profile in [ProfileRegistry] whose
// `AcceptsTypes` includes t. The result is sorted by profile name so the
// output is deterministic for `pki profiles --for <type>` and similar
// introspection paths. Returns nil if no profile accepts the type.
//
// This is the 1:N entry point: a single cert type may legitimately be
// validated under multiple named profiles (e.g. `C.FD.AUT` is accepted
// by both `epavau` and `idp`).
func ProfilesForType(t CertificateType) []*Profile {
	var out []*Profile
	seen := map[*Profile]struct{}{}
	for _, p := range ProfileRegistry {
		if _, ok := seen[p]; ok {
			// Registry aliases (e.g. "idp" pointing at the same profile
			// twice) — skip duplicates.
			continue
		}
		if slices.Contains(p.AcceptsTypes, t) {
			out = append(out, p)
			seen[p] = struct{}{}
		}
	}
	sortProfilesByName(out)
	return out
}

// DetectCertificateType classifies cert as one of the gemSpec_PKI
// Tab_PKI_405 certificate types, returning [CertTypeUnknown] if the cert
// carries no recognisable marker.
//
// Detection runs in two phases:
//
//  1. Scan cert.PolicyIdentifiers for a Tab_PKI_405 OID. This is the
//     spec-defined location (the umbrella policy plus the type OID are
//     both asserted in CertificatePolicies) and covers virtually every
//     TI cert in the wild.
//
//  2. Fall back to the Admission extension + KeyUsage/EKU. For older
//     fixtures or non-conforming issuers that elide the type OID from
//     policies, profession/institution OIDs combined with KeyUsage bits
//     give us a best-effort label:
//
//     - HBA (profession OID present)  + contentCommitment → C.HP.QES
//     - HBA + digitalSignature        + clientAuth        → C.HP.AUT
//     - HBA + keyEncipherment/keyAgreement                → C.HP.ENC
//     - SMC-B (institution OID present) + contentCommitment → C.HCI.OSIG
//     - SMC-B + digitalSignature + clientAuth               → C.HCI.AUT
//     - SMC-B + keyEncipherment/keyAgreement                → C.HCI.ENC
//     - eGK (Versicherter OID present) + contentCommitment  → C.CH.QES
//     - eGK + digitalSignature                              → C.CH.AUT
//     - eGK + keyEncipherment                               → C.CH.ENC
//
// Phase 2 is best-effort; when in doubt it returns [CertTypeUnknown]
// rather than guessing.
func DetectCertificateType(cert *x509.Certificate) CertificateType {
	if cert == nil {
		return CertTypeUnknown
	}
	for _, oid := range cert.PolicyIdentifiers {
		if t, ok := certTypeByOID[oid.String()]; ok {
			return t
		}
	}
	return inferFromAdmission(cert)
}

// inferFromAdmission is the Phase-2 backstop. Public surfaces should call
// [DetectCertificateType] which guarantees the Phase-1 scan ran first.
func inferFromAdmission(cert *x509.Certificate) CertificateType {
	adm, err := ParseAdmissionStatement(cert)
	if err != nil || adm == nil {
		return CertTypeUnknown
	}
	family := classifyAdmissionFamily(adm.ProfessionOids)
	if family == admUnknown {
		return CertTypeUnknown
	}
	usage := classifyKeyUsage(cert)
	switch family {
	case admHBA:
		switch usage {
		case usageQES:
			return CertTypeHpQES
		case usageAUT:
			return CertTypeHpAUT
		case usageENC:
			return CertTypeHpENC
		}
	case admSMCB:
		switch usage {
		case usageQES:
			return CertTypeHciOSIG
		case usageAUT:
			return CertTypeHciAUT
		case usageENC:
			return CertTypeHciENC
		}
	case admEgk:
		switch usage {
		case usageQES:
			return CertTypeChQES
		case usageAUT:
			return CertTypeChAUT
		case usageENC:
			return CertTypeChENC
		}
	}
	return CertTypeUnknown
}

type admFamily int

const (
	admUnknown admFamily = iota
	admHBA
	admSMCB
	admEgk
)

// classifyAdmissionFamily looks at the role-OID arc to decide whether
// the Admission belongs to an HBA (Heilberufsausweis profession OIDs),
// SMC-B (institution OIDs), or eGK (Versicherter OID).
//
// Per gemSpec_OID Tab_PKI_402 / Tab_PKI_403:
//   - 1.2.276.0.76.4.30..48, 178, 232..324 are profession OIDs (HBA)
//   - 1.2.276.0.76.4.49 is OIDProfVersicherter (eGK card holder)
//   - 1.2.276.0.76.4.50..59, 187, 190, 210, 223..231, 242..318+ are
//     institution OIDs (SMC-B); checked via a membership set built from
//     the OIDInst* constants in oids.go.
func classifyAdmissionFamily(professionOids []string) admFamily {
	for _, s := range professionOids {
		if s == OIDProfVersicherter.String() {
			return admEgk
		}
		if _, ok := smcbInstitutionSet[s]; ok {
			return admSMCB
		}
		if _, ok := hbaProfessionSet[s]; ok {
			return admHBA
		}
	}
	return admUnknown
}

// smcbInstitutionSet is the membership set of institution-role OIDs that
// identify an SMC-B's Admission. Derived from the OIDInst* constants in
// oids.go (Tab_PKI_403). Updated in lock-step with that file.
var smcbInstitutionSet = oidSet(
	OIDInstArztpraxis, OIDInstZahnarztpraxis, OIDInstPraxisPsychotherapeut,
	OIDInstKrankenhaus, OIDInstOeffentlicheApo, OIDInstKrankenhausapotheke,
	OIDInstBundeswehrapotheke, OIDInstMobileEinrichtungRettung,
	OIDInstGematik, OIDInstKostentraeger, OIDInstLeoZahnaerzte,
	OIDInstAdvKtr, OIDInstLeoKassenaerztlicheVerein, OIDInstGKVSpitzenverband,
	OIDInstLeoApothekerverband, OIDInstLeoDAV, OIDInstLeoKrankenhausverband,
	OIDInstLeoDKTIG, OIDInstLeoDKG, OIDInstLeoBAEK,
	OIDInstLeoAerztekammer, OIDInstLeoZahnaerztekammer, OIDInstLeoKBV,
	OIDInstLeoBZAEK, OIDInstLeoKZBV, OIDInstPflege, OIDInstGeburtshilfe,
	OIDInstPraxisPhysiotherapeut, OIDInstAugenoptiker, OIDInstHoerakustiker,
	OIDInstOrthopaedieschuhmacher, OIDInstOrthopaedietechniker, OIDInstZahntechniker,
	OIDInstRettungsleitstelle, OIDInstSanitaetsdienstBW, OIDInstOEGD,
	OIDInstArbeitsmedizin, OIDInstVorsorgeReha, OIDInstPflegeberatung,
	OIDInstLeoPsychotherapeuten, OIDInstLeoBPtK, OIDInstLeoLAK,
	OIDInstLeoBAK, OIDInstLeoEGBR, OIDInstLeoHandwerkskammer,
	OIDInstGesundheitsdatenregister, OIDInstAbrechnungsdienstleister,
	OIDInstPKVVerband, OIDInstPraxisErgotherapeut, OIDInstPraxisLogopaede,
	OIDInstHimi, OIDInstFriseur, OIDInstSoziother,
)

// hbaProfessionSet is the membership set of HBA profession-role OIDs.
// Derived from the OIDProf* constants in oids.go (Tab_PKI_402). Excludes
// OIDProfVersicherter which is the eGK marker.
var hbaProfessionSet = oidSet(
	OIDProfArzt, OIDProfZahnarzt, OIDProfApotheker, OIDProfApothekerassistent,
	OIDProfPharmazieingenieur, OIDProfPharmTechnAssistent,
	OIDProfPharmKaufmAngestellter, OIDProfApothekenhelfer,
	OIDProfApothekenassistent, OIDProfPharmAssistent,
	OIDProfApothekenfacharbeiter, OIDProfPharmaziepraktikant, OIDProfFamulant,
	OIDProfPTAPraktikant, OIDProfPKAAuszubildender, OIDProfPsychotherapeut,
	OIDProfPsPsychotherapeut, OIDProfKuJPsychotherapeut, OIDProfRettungsassistent,
	OIDProfNotfallsanitaeter, OIDProfPflegerHPC, OIDProfAltenpflegerHPC,
	OIDProfPflegefachkraftHPC, OIDProfHebammeHPC, OIDProfPhysiotherapeutHPC,
	OIDProfAugenoptikerHPC, OIDProfHoerakustikerHPC,
	OIDProfOrthopaedieschuhmacherHPC, OIDProfOrthopaedietechnikerHPC,
	OIDProfZahntechnikerHPC, OIDProfErgotherapeutHPC, OIDProfLogopaedeHPC,
	OIDProfPodologeHPC, OIDProfErnaehrungstherapeutHPC, OIDProfOrthopaedHPC,
	OIDProfOptoAudioHPC, OIDProfHimiHPC, OIDProfFriseurHPC,
	OIDProfMasseurMBMHPC, OIDProfSoziotherapeut, OIDProfSSSSTherapeut,
	OIDProfDiaetassistent,
)

func oidSet(oids ...asn1.ObjectIdentifier) map[string]struct{} {
	m := make(map[string]struct{}, len(oids))
	for _, o := range oids {
		m[o.String()] = struct{}{}
	}
	return m
}

// keyUsageClass collapses the cert's KeyUsage into the three meaningful
// buckets for cert-type inference. The order of the checks matters:
// contentCommitment (QES/OSIG) dominates over digitalSignature alone
// (AUT), which dominates over keyEncipherment/keyAgreement (ENC).
type keyUsageClass int

const (
	usageOther keyUsageClass = iota
	usageQES
	usageAUT
	usageENC
)

func classifyKeyUsage(cert *x509.Certificate) keyUsageClass {
	ku := cert.KeyUsage
	if ku&x509.KeyUsageContentCommitment != 0 {
		return usageQES
	}
	if ku&x509.KeyUsageDigitalSignature != 0 {
		return usageAUT
	}
	if ku&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) != 0 {
		return usageENC
	}
	return usageOther
}
