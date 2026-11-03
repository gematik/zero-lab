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
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

// ErrNoAdmissionStatement says a certificate has no admission extension, as opposed to one that
// cannot be read.
var ErrNoAdmissionStatement = errors.New("tipki: certificate has no admission extension")

// AdmissionStatement is what an admission extension says of the certificate's holder.
type AdmissionStatement struct {
	// ProfessionItems is the profession or institution in words, e.g. Arztpraxis.
	ProfessionItems []string
	// ProfessionOIDs are the profession or institution OIDs (Tab_PKI_402, 403, 406).
	ProfessionOIDs []string
	// RegistrationNumber is e.g. a Telematik-ID; empty if the extension has none.
	RegistrationNumber string
}

// Admission decodes cert's admission extension (1.3.36.8.3.3).
func Admission(cert *x509.Certificate) (*AdmissionStatement, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid.AdmissionExtension {
			return ParseAdmission(ext.Value)
		}
	}
	return nil, ErrNoAdmissionStatement
}

// ParseAdmission decodes the DER value of an admission extension, which is the ISIS-MTT syntax:
//
//	AdmissionSyntax ::= SEQUENCE {
//	  admissionAuthority GeneralName OPTIONAL,
//	  contentsOfAdmissions SEQUENCE OF Admissions }
//	Admissions ::= SEQUENCE {
//	  admissionAuthority [0] EXPLICIT GeneralName OPTIONAL,
//	  namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL,
//	  professionInfos SEQUENCE OF ProfessionInfo }
//	ProfessionInfo ::= SEQUENCE {
//	  namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
//	  professionItems SEQUENCE OF DirectoryString,
//	  professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
//	  registrationNumber PrintableString OPTIONAL,
//	  addProfessionInfo OCTET STRING OPTIONAL }
//
// Everything is decoded, so a malformed later element refuses the whole. What it returns comes
// from the first profession info of the first admission; TI certificates carry exactly one
// (PROF-010, PROF-011).
func ParseAdmission(der []byte) (*AdmissionStatement, error) {
	outer, err := element(der)
	if err != nil {
		return nil, fmt.Errorf("tipki: admission extension: %w", err)
	}
	if !isSequence(outer) {
		return nil, errors.New("tipki: admission extension: not a SEQUENCE")
	}
	fields, err := elements(outer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tipki: admission extension: %w", err)
	}
	if len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific {
		fields = fields[1:]
	}
	if len(fields) != 1 || !isSequence(fields[0]) {
		return nil, errors.New("tipki: admission extension: not an AdmissionSyntax")
	}
	admissions, err := elements(fields[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("tipki: admission extension: %w", err)
	}
	if len(admissions) == 0 {
		return nil, errors.New("tipki: admission extension: no contents of admissions")
	}
	var first *AdmissionStatement
	for _, admission := range admissions {
		statement, err := parseAdmissions(admission)
		if err != nil {
			return nil, fmt.Errorf("tipki: admission extension: %w", err)
		}
		if first == nil {
			first = statement
		}
	}
	return first, nil
}

func parseAdmissions(admission asn1.RawValue) (*AdmissionStatement, error) {
	if !isSequence(admission) {
		return nil, errors.New("admissions: not a SEQUENCE")
	}
	fields, err := elements(admission.Bytes)
	if err != nil {
		return nil, err
	}
	fields = skipTagged(fields, 0)
	fields = skipTagged(fields, 1)
	if len(fields) != 1 || !isSequence(fields[0]) {
		return nil, errors.New("admissions: no profession infos")
	}
	infos, err := elements(fields[0].Bytes)
	if err != nil {
		return nil, err
	}
	if len(infos) == 0 {
		return nil, errors.New("admissions: no profession infos")
	}
	var first *AdmissionStatement
	for _, info := range infos {
		statement, err := parseProfessionInfo(info)
		if err != nil {
			return nil, err
		}
		if first == nil {
			first = statement
		}
	}
	return first, nil
}

func parseProfessionInfo(info asn1.RawValue) (*AdmissionStatement, error) {
	if !isSequence(info) {
		return nil, errors.New("profession info: not a SEQUENCE")
	}
	fields, err := elements(info.Bytes)
	if err != nil {
		return nil, err
	}
	fields = skipTagged(fields, 0)
	if len(fields) == 0 || !isSequence(fields[0]) {
		return nil, errors.New("profession info: no profession items")
	}
	statement := new(AdmissionStatement)
	items, err := elements(fields[0].Bytes)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		text, err := directoryString(item)
		if err != nil {
			return nil, err
		}
		statement.ProfessionItems = append(statement.ProfessionItems, text)
	}
	fields = fields[1:]
	if len(fields) > 0 && isSequence(fields[0]) {
		oids, err := elements(fields[0].Bytes)
		if err != nil {
			return nil, err
		}
		for _, raw := range oids {
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(raw.FullBytes, &id); err != nil {
				return nil, fmt.Errorf("profession OID: %w", err)
			}
			statement.ProfessionOIDs = append(statement.ProfessionOIDs, id.String())
		}
		fields = fields[1:]
	}
	if len(fields) > 0 && isUniversal(fields[0], asn1.TagPrintableString) {
		if !printable(fields[0].Bytes) {
			return nil, errors.New("registration number: not a PrintableString")
		}
		statement.RegistrationNumber = string(fields[0].Bytes)
		fields = fields[1:]
	}
	if len(fields) > 0 && isUniversal(fields[0], asn1.TagOctetString) {
		fields = fields[1:]
	}
	if len(fields) != 0 {
		return nil, errors.New("profession info: an unexpected element")
	}
	return statement, nil
}

func element(der []byte) (asn1.RawValue, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(der, &value)
	if err != nil {
		return value, err
	}
	if len(rest) != 0 {
		return value, errors.New("data after the element")
	}
	return value, nil
}

func elements(der []byte) ([]asn1.RawValue, error) {
	var values []asn1.RawValue
	for len(der) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(der, &value)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		der = rest
	}
	return values, nil
}

func isSequence(value asn1.RawValue) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == asn1.TagSequence && value.IsCompound
}

func isUniversal(value asn1.RawValue, tag int) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == tag && !value.IsCompound
}

func skipTagged(fields []asn1.RawValue, tag int) []asn1.RawValue {
	if len(fields) > 0 && fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == tag {
		return fields[1:]
	}
	return fields
}

func directoryString(value asn1.RawValue) (string, error) {
	switch {
	case isUniversal(value, asn1.TagUTF8String) && utf8.Valid(value.Bytes):
		return string(value.Bytes), nil
	case isUniversal(value, asn1.TagPrintableString) && printable(value.Bytes):
		return string(value.Bytes), nil
	case isUniversal(value, asn1.TagT61String) && ascii(value.Bytes):
		return string(value.Bytes), nil
	case isUniversal(value, asn1.TagBMPString):
		if text, ok := bmpString(value.Bytes); ok {
			return text, nil
		}
	}
	return "", errors.New("profession item: not a DirectoryString")
}

func ascii(text []byte) bool {
	return !slices.ContainsFunc(text, func(b byte) bool { return b >= 0x80 })
}

// bmpString decodes UCS-2: two bytes per character, and no surrogates, which only UTF-16 has.
func bmpString(text []byte) (string, bool) {
	if len(text)%2 != 0 {
		return "", false
	}
	runes := make([]rune, 0, len(text)/2)
	for i := 0; i < len(text); i += 2 {
		unit := rune(text[i])<<8 | rune(text[i+1])
		if unit >= 0xd800 && unit <= 0xdfff {
			return "", false
		}
		runes = append(runes, unit)
	}
	return string(runes), true
}

// printable is X.680's PrintableString alphabet, stricter than what encoding/asn1 lets through.
func printable(text []byte) bool {
	for _, b := range text {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == ' ', b == '\'', b == '(', b == ')', b == '+', b == ',', b == '-', b == '.',
			b == '/', b == ':', b == '=', b == '?':
		default:
			return false
		}
	}
	return true
}
