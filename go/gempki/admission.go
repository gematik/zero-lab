package gempki

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gematik/zero-lab/go/gempki/oid"
)

/*
admissionSyntax ::= SEQUENCE

	{
	  admissionAuthority GeneralName OPTIONAL,
	  contentsOfAdmissions SEQUENCE OF admissions
	}

admissions ::= SEQUENCE

	{
	  admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
	  namingAuthority [1] EXPLICIT namingAuthority OPTIONAL
	  professionInfos SEQUENCE OF professionInfo
	}

namingAuthority ::= SEQUENCE

	{
	  namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
	  namingAuthorityUrl IA5String OPTIONAL,
	  namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
	}

professionInfo ::= SEQUENCE

	{
	  namingAuthority [0] EXPLICIT namingAuthority OPTIONAL,
	  professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
	  professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
	  registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
	  addProfessionInfo OCTET STRING OPTIONAL
	}
*/
type AdmissionStatement struct {
	ProfessionItems    []string `json:"professionItems"`
	ProfessionOids     []string `json:"professionOids"`
	RegistrationNumber string   `json:"registrationNumber"`
}

type admissionSyntax struct {
	AdmissionAuthorityRaw *asn1.RawValue
	ContentsOfAdmissions  []admissions
}

type admissions struct {
	AdmissionAuthority asn1.RawValue    `asn1:"tag:0,optional"`
	NamingAuthority    namingAuthority  `asn1:"tag:1,optional"`
	ProfessionInfos    []professionInfo `asn1:"sequence"`
}
type namingAuthority struct {
	NamingAuthorityId   asn1.ObjectIdentifier `asn1:"optional"`
	NamingAuthorityUrl  string                `asn1:"ia5,optional"`
	NamingAuthorityText string                `asn1:"utf8,optional"`
}
type professionInfo struct {
	NamingAuthority    *namingAuthority        `asn1:"tag:0,optional,explicit"`
	ProfessionItems    []string                `asn1:"directory,sequence"`
	ProfessionOids     []asn1.ObjectIdentifier `asn1:"optional,sequence"`
	RegistrationNumber string                  `asn1:"printable,optional"`
	AddProfessionInfo  []byte                  `asn1:"optional"`
}

// ErrNoAdmissionStatement is returned by [ParseAdmissionStatement] when the
// certificate carries no admission extension at all — as opposed to one that
// could not be decoded. Callers that treat "no roles asserted" as an
// ordinary outcome match it with errors.Is.
var ErrNoAdmissionStatement = errors.New("gempki: certificate has no admission statement extension")

// ParseAdmissionStatement decodes the gematik admission extension
// (1.3.36.8.3.3) carrying the profession items, OIDs and registration number.
func ParseAdmissionStatement(cert *x509.Certificate) (*AdmissionStatement, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.AdmissionExtension) {
			as, err := parseAdmissionSyntax(ext.Value)
			if err != nil {
				return nil, err
			}
			return convertAdmissionSyntax(as)
		}
	}
	return nil, ErrNoAdmissionStatement
}

func readSeq(b []byte) ([]asn1.RawValue, error) {
	var elems []asn1.RawValue
	rest := b
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, err
		}
		elems = append(elems, v)
	}
	return elems, nil
}

func parseAdmissionSyntax(asn1data []byte) (*admissionSyntax, error) {
	admission := new(admissionSyntax)

	raw := new(asn1.RawValue)

	_, err2 := asn1.Unmarshal(asn1data, raw)
	if err2 != nil {
		return nil, fmt.Errorf("failed to unmarshal admission statement: %w", err2)
	}

	seq, err := readSeq(raw.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read sequence: %w", err)
	}

	var admissionsBytes []byte

	if len(seq) == 1 {
		admissionsBytes = seq[0].FullBytes
	} else if len(seq) == 2 {
		admissionsBytes = seq[1].FullBytes
		admission.AdmissionAuthorityRaw = &seq[0]
	} else {
		return nil, fmt.Errorf("unexpected number of elements in admission statement: %d", len(seq))
	}
	_, err = asn1.Unmarshal(admissionsBytes, &admission.ContentsOfAdmissions)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal contentsOfAdmissions: %w", err)
	}

	return admission, nil
}

func convertAdmissionSyntax(as *admissionSyntax) (*AdmissionStatement, error) {
	if len(as.ContentsOfAdmissions) == 0 {
		return nil, fmt.Errorf("no contents of admissions found")
	}

	// take the first one
	admissions := as.ContentsOfAdmissions[0]
	if len(admissions.ProfessionInfos) == 0 {
		return nil, fmt.Errorf("no profession infos found")
	}
	// take the first one
	professionInfo := admissions.ProfessionInfos[0]

	var professionOids []string
	for _, oid := range professionInfo.ProfessionOids {
		professionOids = append(professionOids, oid.String())
	}

	return &AdmissionStatement{
		ProfessionItems:    professionInfo.ProfessionItems,
		ProfessionOids:     professionOids,
		RegistrationNumber: professionInfo.RegistrationNumber,
	}, nil
}
