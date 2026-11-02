// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package tipki

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

// CertificateType is a gemSpec_PKI Tab_PKI_405 type under its specification name, plus C.TSL.SIG,
// the TSL signer of Tab_PKI_252_01, which its policy identifies.
type CertificateType string

// The types, in Tab_PKI_405 order, then C.TSL.SIG.
const (
	CertChQes   CertificateType = "C.CH.QES"
	CertChSig   CertificateType = "C.CH.SIG"
	CertChEnc   CertificateType = "C.CH.ENC"
	CertChEncv  CertificateType = "C.CH.ENCV"
	CertChAut   CertificateType = "C.CH.AUT"
	CertChAutn  CertificateType = "C.CH.AUTN"
	CertHpQes   CertificateType = "C.HP.QES"
	CertHpAut   CertificateType = "C.HP.AUT"
	CertHpEnc   CertificateType = "C.HP.ENC"
	CertHciAut  CertificateType = "C.HCI.AUT"
	CertHciEnc  CertificateType = "C.HCI.ENC"
	CertHciOsig CertificateType = "C.HCI.OSIG"
	CertFdTLSS  CertificateType = "C.FD.TLS-S"
	CertFdTLSC  CertificateType = "C.FD.TLS-C"
	CertFdSig   CertificateType = "C.FD.SIG"
	CertFdEnc   CertificateType = "C.FD.ENC"
	CertFdAut   CertificateType = "C.FD.AUT"
	CertFdOsig  CertificateType = "C.FD.OSIG"
	CertZdTLSS  CertificateType = "C.ZD.TLS-S"
	CertZdSig   CertificateType = "C.ZD.SIG"
	CertHskSig  CertificateType = "C.HSK.SIG"
	CertHskEnc  CertificateType = "C.HSK.ENC"
	CertGemVer  CertificateType = "C.GEM.VER"
	CertTslSig  CertificateType = "C.TSL.SIG"
)

// TypeSpec is the baseline every certificate of a type must meet. Every entry is a floor and never
// an equality: the key usage bits must all be set, one extended key usage must be present, every
// policy asserted, one role in the admission extension. An empty entry requires nothing.
type TypeSpec struct {
	KeyUsage    x509.KeyUsage
	ExtKeyUsage []string
	Policies    []string
	RoleOIDs    []string
}

type typeEntry struct {
	id   string
	spec TypeSpec
}

// AllCertificateTypes returns every type, in the order of the specification.
func AllCertificateTypes() []CertificateType {
	return []CertificateType{CertChQes, CertChSig, CertChEnc, CertChEncv, CertChAut, CertChAutn, CertHpQes, CertHpAut, CertHpEnc, CertHciAut, CertHciEnc, CertHciOsig, CertFdTLSS, CertFdTLSC, CertFdSig, CertFdEnc, CertFdAut, CertFdOsig, CertZdTLSS, CertZdSig, CertHskSig, CertHskEnc, CertGemVer, CertTslSig}
}

// The X.509 profile tables of gemSpec_PKI (Tab_PKI_232 to 300), ECDSA branch. Optional entries are
// left out, as in ti-pki. Fachdienst types carry no baseline role: a profile discriminates on it.
var typeTable = map[CertificateType]typeEntry{
	CertChQes: {
		id: oid.CertTypeEgkQES,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkQES},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertChSig: {
		id: oid.CertTypeEgkSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkSIG},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertChEnc: {
		id: oid.CertTypeEgkENC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkENC},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertChEncv: {
		id: oid.CertTypeEgkENCV,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkENCV},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertChAut: {
		id: oid.CertTypeEgkAUT,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkAUT},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertChAutn: {
		id: oid.CertTypeEgkAUTN,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []string{clientAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeEgkAUTN},
			RoleOIDs:    []string{oid.ProfVersicherter},
		},
	},
	CertHpQes: {
		id: oid.CertTypeHbaQES,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyHbaCP, oid.CertTypeHbaQES},
			RoleOIDs:    oid.Professions,
		},
	},
	CertHpAut: {
		id: oid.CertTypeHbaAUT,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
			ExtKeyUsage: []string{clientAuth, emailProtection},
			Policies:    []string{oid.PolicyHbaCP, oid.CertTypeHbaAUT},
			RoleOIDs:    oid.Professions,
		},
	},
	CertHpEnc: {
		id: oid.CertTypeHbaENC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyHbaCP, oid.CertTypeHbaENC},
			RoleOIDs:    oid.Professions,
		},
	},
	CertHciAut: {
		id: oid.CertTypeSmcBAUT,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []string{clientAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeSmcBAUT},
			RoleOIDs:    oid.Institutions,
		},
	},
	CertHciEnc: {
		id: oid.CertTypeSmcBENC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeSmcBENC},
			RoleOIDs:    oid.Institutions,
		},
	},
	CertHciOsig: {
		id: oid.CertTypeSmcBOSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeSmcBOSIG},
			RoleOIDs:    oid.Institutions,
		},
	},
	CertFdTLSS: {
		id: oid.CertTypeFdTLSS,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []string{serverAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdTLSS},
			RoleOIDs:    nil,
		},
	},
	CertFdTLSC: {
		id: oid.CertTypeFdTLSC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []string{clientAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdTLSC},
			RoleOIDs:    nil,
		},
	},
	CertFdSig: {
		id: oid.CertTypeFdSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdSIG},
			RoleOIDs:    nil,
		},
	},
	CertFdEnc: {
		id: oid.CertTypeFdENC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdENC},
			RoleOIDs:    nil,
		},
	},
	CertFdAut: {
		id: oid.CertTypeFdAUT,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdAUT},
			RoleOIDs:    nil,
		},
	},
	CertFdOsig: {
		id: oid.CertTypeFdOSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeFdOSIG},
			RoleOIDs:    nil,
		},
	},
	CertZdTLSS: {
		id: oid.CertTypeZdTLSS,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []string{serverAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeZdTLSS},
			RoleOIDs:    nil,
		},
	},
	CertZdSig: {
		id: oid.CertTypeZdSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeZdSIG},
			RoleOIDs:    nil,
		},
	},
	CertHskSig: {
		id: oid.CertTypeHskSIG,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: []string{clientAuth, serverAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeHskSIG},
			RoleOIDs:    []string{oid.TechRoleHSK},
		},
	},
	CertHskEnc: {
		id: oid.CertTypeHskENC,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageKeyAgreement,
			ExtKeyUsage: []string{clientAuth, serverAuth},
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeHskENC},
			RoleOIDs:    []string{oid.TechRoleHSK},
		},
	},
	CertGemVer: {
		id: oid.CertTypeGemVER,
		spec: TypeSpec{
			KeyUsage:    0,
			ExtKeyUsage: nil,
			Policies:    []string{oid.PolicyGemOrCP, oid.CertTypeGemVER},
			RoleOIDs:    nil,
		},
	},
	CertTslSig: {
		id: oid.PolicyGemTSLSigner,
		spec: TypeSpec{
			KeyUsage:    x509.KeyUsageContentCommitment,
			ExtKeyUsage: []string{tslSigning},
			Policies:    []string{oid.PolicyGemTSLSigner},
			RoleOIDs:    nil,
		},
	},
}

// OID is the type's Tab_PKI_405 identifier; for C.TSL.SIG, which has none, the policy identifying it.
func (t CertificateType) OID() string { return typeTable[t].id }

// Spec is the baseline of the type.
func (t CertificateType) Spec() TypeSpec { return typeTable[t].spec }

func (t CertificateType) String() string { return string(t) }

// FoldName folds a type or profile name for comparison: case ignored, "." and "-" alike, a leading
// "C." dropped. So C.FD.TLS-S, FD.TLS-S and fd-tls-s compare equal.
func FoldName(name string) string {
	folded := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), ".", "-")
	return strings.TrimPrefix(folded, "c-")
}

// ParseCertificateType finds a type by its name, folded by [FoldName].
func ParseCertificateType(name string) (CertificateType, error) {
	wanted := FoldName(name)
	for _, t := range AllCertificateTypes() {
		if FoldName(string(t)) == wanted {
			return t, nil
		}
	}
	return "", fmt.Errorf("tipki: unknown certificate type %q", name)
}

func typeByOID(id string) (CertificateType, bool) {
	for _, t := range AllCertificateTypes() {
		if t.OID() == id {
			return t, true
		}
	}
	return "", false
}

// DetectCertificateType classifies cert, false if it has no recognisable marker (PROF-001).
//
// First the type OID in the certificate policies, where gemSpec_PKI puts it. Otherwise, for issuers
// that leave it out, the admission extension and the key usage: an HBA profession, an SMC-B
// institution or the eGK insurant, with contentCommitment before digitalSignature before
// keyEncipherment or keyAgreement. An eGK's AUT and ENC certificates have pseudonymous siblings
// with the same admission and key usage, so those stay undecided (PROF-002).
func DetectCertificateType(cert *x509.Certificate) (CertificateType, bool) {
	for _, policy := range cert.Policies {
		if t, ok := typeByOID(policy.String()); ok {
			return t, true
		}
	}
	return typeFromAdmission(cert)
}

func typeFromAdmission(cert *x509.Certificate) (CertificateType, bool) {
	admission, err := Admission(cert)
	if err != nil {
		return "", false
	}
	const (
		hba = iota + 1
		smcb
		egk
	)
	family := 0
	for _, role := range admission.ProfessionOIDs {
		switch {
		case role == oid.ProfVersicherter:
			family = egk
		case slices.Contains(oid.Institutions, role):
			family = smcb
		case slices.Contains(oid.Professions, role):
			family = hba
		}
		if family != 0 {
			break
		}
	}
	const (
		qes = iota + 1
		aut
		enc
	)
	usage := 0
	switch {
	case cert.KeyUsage&x509.KeyUsageContentCommitment != 0:
		usage = qes
	case cert.KeyUsage&x509.KeyUsageDigitalSignature != 0:
		usage = aut
	case cert.KeyUsage&(x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement) != 0:
		usage = enc
	}
	switch [2]int{family, usage} {
	case [2]int{hba, qes}:
		return CertHpQes, true
	case [2]int{hba, aut}:
		return CertHpAut, true
	case [2]int{hba, enc}:
		return CertHpEnc, true
	case [2]int{smcb, qes}:
		return CertHciOsig, true
	case [2]int{smcb, aut}:
		return CertHciAut, true
	case [2]int{smcb, enc}:
		return CertHciEnc, true
	case [2]int{egk, qes}:
		return CertChQes, true
	}
	return "", false
}

// extKeyUsages reads the extension itself: crypto/x509 folds what it does not know, such as the
// TSL signing purpose, into a separate list.
func extKeyUsages(cert *x509.Certificate) []string {
	for _, ext := range cert.Extensions {
		if ext.Id.String() != extKeyUsageExtension {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &oids); err != nil {
			return nil
		}
		usages := make([]string, len(oids))
		for i, id := range oids {
			usages[i] = id.String()
		}
		return usages
	}
	return nil
}
