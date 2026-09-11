package gempki

import (
	"crypto/x509"
	"encoding/asn1"
	"github.com/gematik/zero-lab/go/gempki/oid"
)

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
// The fallback is best-effort; when in doubt it returns [CertTypeUnknown]
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

// inferFromAdmission is the fallback behind [DetectCertificateType], which
// always tries the policy scan first.
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
//   - 1.2.276.0.76.4.49 is oid.ProfVersicherter (eGK card holder)
//   - 1.2.276.0.76.4.50..59, 187, 190, 210, 223..231, 242..318+ are
//     institution OIDs (SMC-B); checked via a membership set built from
//     the oid.Inst* constants in oids.go.
func classifyAdmissionFamily(professionOids []string) admFamily {
	for _, s := range professionOids {
		if s == oid.ProfVersicherter.String() {
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

// smcbInstitutionSet and hbaProfessionSet are the whole Tab_PKI_403 /
// Tab_PKI_402 tables as membership sets: a certificate whose admission
// extension asserts any of them is an SMC-B or an HBA respectively.
var (
	smcbInstitutionSet = oidSet(oid.Institutions...)
	hbaProfessionSet   = oidSet(oid.Professions...)
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
