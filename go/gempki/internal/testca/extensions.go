package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1" //nolint:gosec // SKI/AKI use SHA-1 per RFC 5280 §4.2.1.2 method (1)
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// buildExtensions assembles the X.509v3 extensions for one cert from
// CertOptions. Order matches gemSpec_PKI emission order: SKI, AKI,
// BasicConstraints, KeyUsage, ExtKeyUsage, SAN, CertificatePolicies, then
// ExtraExtensions.
func buildExtensions(opts CertOptions, subjectPub, issuerPub *ecdsa.PublicKey) ([]pkix.Extension, error) {
	exts := make([]pkix.Extension, 0, 8+len(opts.ExtraExtensions))

	skid := keyIdentifier(subjectPub)
	skidDER, err := asn1.Marshal(skid)
	if err != nil {
		return nil, fmt.Errorf("testca: marshal SKI: %w", err)
	}
	exts = append(exts, pkix.Extension{Id: oidExtSubjectKeyID, Value: skidDER})

	akid := keyIdentifier(issuerPub)
	akiDER, err := asn1.Marshal(authorityKeyIdentifier{KeyIdentifier: akid})
	if err != nil {
		return nil, fmt.Errorf("testca: marshal AKI: %w", err)
	}
	exts = append(exts, pkix.Extension{Id: oidExtAuthorityKeyID, Value: akiDER})

	if opts.BasicConstraints || opts.IsCA {
		bc := basicConstraints{IsCA: opts.IsCA}
		if opts.MaxPathLenZero {
			bc.MaxPathLen = 0
			bc.MaxPathLenSet = true
		} else if opts.MaxPathLen > 0 {
			bc.MaxPathLen = opts.MaxPathLen
			bc.MaxPathLenSet = true
		}
		bcDER, err := marshalBasicConstraints(bc)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidExtBasicConstraints, Critical: true, Value: bcDER})
	}

	if opts.KeyUsage != 0 {
		kuDER, err := marshalKeyUsage(opts.KeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidExtKeyUsage, Critical: true, Value: kuDER})
	}

	if len(opts.ExtKeyUsage) > 0 {
		ekuDER, err := marshalExtKeyUsage(opts.ExtKeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidExtExtKeyUsage, Value: ekuDER})
	}

	if len(opts.DNSNames) > 0 {
		sanDER, err := marshalSAN(opts.DNSNames)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidExtSubjectAltName, Value: sanDER})
	}

	if len(opts.CertificatePolicies) > 0 {
		polDER, err := marshalPolicies(opts.CertificatePolicies)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidExtCertificatePol, Value: polDER})
	}

	exts = append(exts, opts.ExtraExtensions...)
	return exts, nil
}

// keyIdentifier returns the SHA-1 hash of the SubjectPublicKey BIT STRING
// per RFC 5280 §4.2.1.2 method (1). See the SEC1 point comment in cert.go for
// why we cannot use crypto/ecdh here.
func keyIdentifier(pub *ecdsa.PublicKey) []byte {
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck
	h := sha1.Sum(point)
	return h[:]
}

// authorityKeyIdentifier as encoded in RFC 5280 §4.2.1.1.
// We only emit the keyIdentifier field; authorityCertIssuer / authorityCertSerialNumber are omitted.
type authorityKeyIdentifier struct {
	KeyIdentifier []byte `asn1:"tag:0,optional"`
}

type basicConstraints struct {
	IsCA          bool
	MaxPathLen    int
	MaxPathLenSet bool // tracks "explicitly set"; ASN.1 marshal handles default
}

func marshalBasicConstraints(bc basicConstraints) ([]byte, error) {
	if bc.MaxPathLenSet {
		type bcWithPathLen struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional"`
		}
		return asn1.Marshal(bcWithPathLen{IsCA: bc.IsCA, MaxPathLen: bc.MaxPathLen})
	}
	type bcNoPathLen struct {
		IsCA bool `asn1:"optional"`
	}
	return asn1.Marshal(bcNoPathLen{IsCA: bc.IsCA})
}

// marshalKeyUsage encodes a [crypto/x509.KeyUsage] bit set as the BIT STRING
// expected by RFC 5280 §4.2.1.3. Bits are big-endian inside each byte.
func marshalKeyUsage(ku x509.KeyUsage) ([]byte, error) {
	var bits [2]byte
	if ku&x509.KeyUsageDigitalSignature != 0 {
		bits[0] |= 0x80
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		bits[0] |= 0x40
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		bits[0] |= 0x20
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		bits[0] |= 0x10
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		bits[0] |= 0x08
	}
	if ku&x509.KeyUsageCertSign != 0 {
		bits[0] |= 0x04
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		bits[0] |= 0x02
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		bits[0] |= 0x01
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		bits[1] |= 0x80
	}
	// Trim trailing zero byte if possible (matches stdlib emission).
	length := 2
	for length > 0 && bits[length-1] == 0 {
		length--
	}
	if length == 0 {
		// no usage bits set → emit single zero byte
		return asn1.Marshal(asn1.BitString{Bytes: []byte{0}, BitLength: 0})
	}
	// Determine number of unused bits in the last byte.
	last := bits[length-1]
	unused := 0
	for unused < 8 && last&(1<<unused) == 0 {
		unused++
	}
	return asn1.Marshal(asn1.BitString{Bytes: bits[:length], BitLength: length*8 - unused})
}

// marshalExtKeyUsage encodes ExtendedKeyUsage as SEQUENCE OF OID.
func marshalExtKeyUsage(ekus []x509.ExtKeyUsage) ([]byte, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(ekus))
	for _, eku := range ekus {
		oid, ok := ekuOID(eku)
		if !ok {
			return nil, fmt.Errorf("testca: unsupported ExtKeyUsage %d", eku)
		}
		oids = append(oids, oid)
	}
	return asn1.Marshal(oids)
}

func ekuOID(eku x509.ExtKeyUsage) (asn1.ObjectIdentifier, bool) {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, true
	case x509.ExtKeyUsageClientAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, true
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, true
	case x509.ExtKeyUsageEmailProtection:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, true
	case x509.ExtKeyUsageOCSPSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, true
	default:
		// IPsec, time-stamping, Microsoft/Netscape SGC, etc. aren't used by
		// the TI-PKI; rather than enumerate them, fall through to "unknown."
		return nil, false
	}
}

// marshalSAN emits a SubjectAltName with only dNSName entries.
func marshalSAN(dnsNames []string) ([]byte, error) {
	values := make([]asn1.RawValue, 0, len(dnsNames))
	for _, name := range dnsNames {
		values = append(values, asn1.RawValue{
			Tag:   2, // dNSName [2] IMPLICIT IA5String
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(name),
		})
	}
	return asn1.Marshal(values)
}

// marshalPolicies emits CertificatePolicies = SEQUENCE OF PolicyInformation.
// We emit only the policy OID; PolicyQualifierInfos are omitted.
func marshalPolicies(oids []asn1.ObjectIdentifier) ([]byte, error) {
	type policyInfo struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}
	infos := make([]policyInfo, 0, len(oids))
	for _, oid := range oids {
		infos = append(infos, policyInfo{PolicyIdentifier: oid})
	}
	return asn1.Marshal(infos)
}

// AdmissionExtension builds an extension carrying the gematik Admission
// (ISIS-MTT) profession info for one professionItem + professionOID +
// registrationNumber. This is sufficient for testca's needs; the more elaborate
// nested structures with admissionAuthority / namingAuthority are out of scope.
//
// Returned extension is non-critical, matching real TI cards.
func AdmissionExtension(professionItem string, professionOID asn1.ObjectIdentifier, registrationNumber string) (pkix.Extension, error) {
	type professionInfo struct {
		ProfessionItems    []string                `asn1:"sequence"`
		ProfessionOids     []asn1.ObjectIdentifier `asn1:"sequence"`
		RegistrationNumber string                  `asn1:"printable"`
	}
	type admissions struct {
		ProfessionInfos []professionInfo `asn1:"sequence"`
	}
	type admissionSyntax struct {
		ContentsOfAdmissions []admissions `asn1:"sequence"`
	}
	val := admissionSyntax{
		ContentsOfAdmissions: []admissions{{
			ProfessionInfos: []professionInfo{{
				ProfessionItems:    []string{professionItem},
				ProfessionOids:     []asn1.ObjectIdentifier{professionOID},
				RegistrationNumber: registrationNumber,
			}},
		}},
	}
	der, err := asn1.Marshal(val)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("testca: marshal admission extension: %w", err)
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 36, 8, 3, 3},
		Value: der,
	}, nil
}
