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
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/tipki/oid"
)

const (
	// MaxTSLLen is the most a list may have (TSLDET-006). The published ones are about 600 KB.
	MaxTSLLen = 16 * 1024 * 1024
	// MaxDetachedSignatureLen is the most a signature file may have (TSLDET-001).
	MaxDetachedSignatureLen = 8192

	serviceTypeCAPKC         = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
	serviceTypeTSLCertChange = "http://uri.etsi.org/TrstSvc/Svctype/TSLServiceCertChange"
	testOnlyMarker           = "TEST-ONLY"
	primaryLocation          = "1.2.276.0.76.4.120"
	backupLocation           = "1.2.276.0.76.4.121"

	// MinSequenceNumber is the lowest TSLSequenceNumber a list may have (TSLSIG-053).
	MinSequenceNumber     = 10000
	serviceStatusInAccord = "http://uri.etsi.org/TrstSvc/Svcstatus/inaccord"
	serviceStatusGranted  = "http://uri.etsi.org/TrstSvc/Svcstatus/granted"
	serviceStatusRevoked  = "http://uri.etsi.org/TrstSvc/Svcstatus/revoked"
)

var (
	tslPlaceholder  = oid.MustParse("1.2.276.0.76.4.124")
	ecdsaWithSHA256 = oid.MustParse("1.2.840.10045.4.3.2")
)

// TSLError says why a list was refused, by the code and rule of spec/tsl-detached and spec/tsl-xmldsig.
type TSLError struct {
	Code   string
	Rule   string
	Detail string
}

func (e *TSLError) Error() string {
	return fmt.Sprintf("tipki: TSL: %s (%s): %s", e.Code, e.Rule, e.Detail)
}

// DetachedSignature is a parsed signature file, not yet verified against a list.
type DetachedSignature struct {
	// Signer is the certificate the file carries, not yet authenticated.
	Signer *x509.Certificate
	// Signature is the DER ECDSA-Sig-Value.
	Signature []byte
}

// ParseDetachedSignature parses a signature file (TSLDET-001 to 004):
// SEQUENCE { AlgorithmIdentifier, BIT STRING, Certificate }.
func ParseDetachedSignature(sig []byte) (*DetachedSignature, error) {
	malformed := func(rule, format string, args ...any) error {
		return &TSLError{"detached_signature_error", rule, fmt.Sprintf(format, args...)}
	}
	if len(sig) > MaxDetachedSignatureLen {
		return nil, malformed("TSLDET-001", "%d bytes, more than a signature file may have", len(sig))
	}
	outer, err := element(sig)
	if err != nil {
		return nil, malformed("TSLDET-001", "%v", err)
	}
	if !isSequence(outer) {
		return nil, malformed("TSLDET-001", "not a SEQUENCE")
	}
	fields, err := elements(outer.Bytes)
	if err != nil {
		return nil, malformed("TSLDET-001", "%v", err)
	}
	if len(fields) != 3 || !isSequence(fields[0]) || !isSequence(fields[2]) ||
		fields[1].Class != asn1.ClassUniversal || fields[1].Tag != asn1.TagBitString {
		return nil, malformed("TSLDET-001", "not a SEQUENCE of AlgorithmIdentifier, BIT STRING and Certificate")
	}
	algorithm, err := elements(fields[0].Bytes)
	if err != nil || len(algorithm) == 0 {
		return nil, malformed("TSLDET-001", "the AlgorithmIdentifier does not parse")
	}
	var id asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algorithm[0].FullBytes, &id); err != nil || len(algorithm) != 1 || !ecdsaWithSHA256.EqualASN1OID(id) {
		return nil, malformed("TSLDET-002", "the algorithm is not ecdsa-with-SHA256 without parameters")
	}
	if len(fields[1].Bytes) == 0 {
		return nil, malformed("TSLDET-001", "an empty BIT STRING")
	}
	if fields[1].Bytes[0] != 0 {
		return nil, malformed("TSLDET-003", "the signature BIT STRING has unused bits")
	}
	value := fields[1].Bytes[1:]
	if !validSignatureValue(value) {
		return nil, malformed("TSLDET-003", "the signature value is not a DER ECDSA-Sig-Value with r and s in range")
	}
	signer, err := ParseCertificate(fields[2].FullBytes)
	if err != nil {
		return nil, &TSLError{"tsl_cert_extraction_error", "TSLDET-004", err.Error()}
	}
	key, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != brainpool.P256r1() {
		return nil, &TSLError{"tsl_cert_extraction_error", "TSLDET-004", "the signer key is not on brainpoolP256r1"}
	}
	return &DetachedSignature{Signer: signer, Signature: value}, nil
}

func validSignatureValue(value []byte) bool {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(value, &parsed)
	if err != nil || len(rest) != 0 {
		return false
	}
	n := brainpool.P256r1().Params().N
	inRange := func(v *big.Int) bool { return v.Sign() > 0 && v.Cmp(n) < 0 }
	return inRange(parsed.R) && inRange(parsed.S)
}

// VerifiedTSL is a list whose signature verifies and whose signer a TSL signer anchor issued, read from
// exactly the verified bytes. Warnings holds no_ocsp_check until [VerifiedTSL.CheckSignerStatus] or
// [VerifiedTSL.CheckSignerStatusSupplied] has adopted the signer's status.
type VerifiedTSL struct {
	TSL    *TSL
	Anchor *x509.Certificate
	Signer *x509.Certificate
	// Production says the anchor is no TEST-ONLY CA.
	Production bool
	// SignerStatus is the signer's OCSP result, once adopted.
	SignerStatus *RevocationResult
	Warnings     []*TSLError
}

// TSLState is what is kept of a list to judge the next one (TSLSIG-053). It must survive restarts.
type TSLState struct {
	ID             string
	SequenceNumber uint64
}

// State is the state of the list.
func (v *VerifiedTSL) State() TSLState {
	return TSLState{ID: v.TSL.ID, SequenceNumber: v.TSL.SequenceNumber}
}

// Sequence is how a verified list relates to the stored one.
type Sequence int

const (
	// SequenceNewer is a newer list, or the first one: update.
	SequenceNewer Sequence = iota
	// SequenceSame is the stored list again: no update, no error.
	SequenceSame
)

// CheckSequence compares the list with the stored one (TSLSIG-053): none stored, or another Id and a
// greater number, is newer; the same Id and number is the same. Anything else is refused, and so is a
// number below [MinSequenceNumber]. It is what stops an older signed list from being supplied again.
func (v *VerifiedTSL) CheckSequence(stored *TSLState) (Sequence, error) {
	id, number := v.TSL.ID, v.TSL.SequenceNumber
	if number < MinSequenceNumber {
		return 0, &TSLError{"tsl_id_incorrect", "TSLSIG-053", fmt.Sprintf("sequence number %d is below %d", number, MinSequenceNumber)}
	}
	switch {
	case stored == nil:
		return SequenceNewer, nil
	case id == stored.ID && number == stored.SequenceNumber:
		return SequenceSame, nil
	case id != stored.ID && number > stored.SequenceNumber:
		return SequenceNewer, nil
	}
	return 0, &TSLError{"tsl_id_incorrect", "TSLSIG-053", fmt.Sprintf("Id %q with sequence number %d does not follow Id %q with %d", id, number, stored.ID, stored.SequenceNumber)}
}

// VerifyTSL authenticates list by its signature file (spec/tsl-detached), against the TSL signer CAs in
// signerAnchors at now, and reads it. The list is used until its NextUpdate plus grace, and a server has
// a grace of zero. The signature covers the list's bytes as received; nothing is canonicalized, and
// the XML signature inside the list is not looked at.
func VerifyTSL(list, sig []byte, signerAnchors [][]byte, now time.Time, grace time.Duration) (*VerifiedTSL, error) {
	if len(list) > MaxTSLLen {
		return nil, &TSLError{"tsl_not_wellformed", "TSLDET-006", fmt.Sprintf("%d bytes, more than a list may have", len(list))}
	}
	parsed, err := ParseDetachedSignature(sig)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(list)
	if !ecdsa.VerifyASN1(parsed.Signer.PublicKey.(*ecdsa.PublicKey), digest[:], parsed.Signature) {
		return nil, &TSLError{"detached_signature_error", "TSLDET-005", "the signature value does not verify over the list"}
	}
	anchors := make([]*x509.Certificate, len(signerAnchors))
	for i, der := range signerAnchors {
		if anchors[i], err = ParseCertificate(der); err != nil {
			return nil, &TSLError{"certificate_not_valid_math", "TSLSIG-030", "TSL signer anchor: " + err.Error()}
		}
	}
	anchor, err := issuingAnchor(anchors, parsed.Signer)
	if err != nil {
		return nil, err
	}
	if err := checkTSLSigner(parsed.Signer, anchor, now); err != nil {
		return nil, err
	}
	tsl, err := parseTSL(list)
	if err != nil {
		return nil, &TSLError{"tsl_not_wellformed", "TSLDET-006", "signed content: " + err.Error()}
	}
	verified := &VerifiedTSL{
		TSL: tsl, Anchor: anchor, Signer: parsed.Signer,
		Production: !strings.Contains(anchor.Subject.String(), testOnlyMarker),
	}
	if !tsl.NextUpdate.IsZero() && !now.Before(tsl.NextUpdate) {
		past := fmt.Sprintf("NextUpdate %s has passed at %s", tsl.NextUpdate, now)
		if !now.Before(tsl.NextUpdate.Add(grace)) {
			return nil, &TSLError{"validity_warning_2", "TSLSIG-054", past + ", beyond the grace period"}
		}
		verified.Warnings = append(verified.Warnings, &TSLError{"validity_warning_1", "TSLSIG-054", past})
	}
	verified.Warnings = append(verified.Warnings, announcedAnchors(tsl, anchors)...)
	verified.Warnings = append(verified.Warnings, &TSLError{"no_ocsp_check", "TSLSIG-043", "the signer's OCSP status was not queried"})
	return verified, nil
}

// announcedAnchors warns of each TSL signer CA the list announces that is not configured yet
// (TSLSIG-060). It is not adopted: an operator adds it to the configured anchors.
func announcedAnchors(tsl *TSL, anchors []*x509.Certificate) []*TSLError {
	var warnings []*TSLError
	for _, service := range tsl.Services {
		if service.ServiceType != serviceTypeTSLCertChange {
			continue
		}
		what := fmt.Sprintf("%q without a certificate", service.Name)
		if service.Certificate != nil {
			if slices.ContainsFunc(anchors, service.Certificate.Equal) {
				continue
			}
			what = fmt.Sprintf("%s (SHA-256 %x)", service.Certificate.Subject, sha256.Sum256(service.Certificate.Raw))
		}
		from := "an unstated time"
		if !service.StatusStartingTime.IsZero() {
			from = service.StatusStartingTime.String()
		}
		warnings = append(warnings, &TSLError{
			"tsl_anchor_announced", "TSLSIG-060",
			fmt.Sprintf("the TSL announces the TSL signer CA %s from %s; add it to the configured TSL signer anchors", what, from),
		})
	}
	return warnings
}

func issuingAnchor(anchors []*x509.Certificate, signer *x509.Certificate) (*x509.Certificate, error) {
	var named *x509.Certificate
	for _, anchor := range anchors {
		if !bytes.Equal(anchor.RawSubject, signer.RawIssuer) {
			continue
		}
		if len(anchor.SubjectKeyId) > 0 && bytes.Equal(anchor.SubjectKeyId, signer.AuthorityKeyId) {
			return anchor, nil
		}
		if named == nil {
			named = anchor
		}
	}
	if named == nil {
		return nil, &TSLError{"certificate_not_valid_math", "TSLSIG-031", "the signer's issuer " + signer.Issuer.String() + " is no configured TSL signer CA"}
	}
	return named, nil
}

// checkTSLSigner is part B of spec/tsl-xmldsig: issued by the anchor (TSLSIG-031), both valid at now without
// skew (032), and C.TSL.SIG with its key usages exactly (033 to 035).
func checkTSLSigner(signer, anchor *x509.Certificate, now time.Time) error {
	math := func(detail string) error { return &TSLError{"certificate_not_valid_math", "TSLSIG-031", detail} }
	profile := func(detail string) error {
		return &TSLError{"tsl_signer_profile_violation", "TSLSIG-035", "not C.TSL.SIG: " + detail}
	}
	if !anchor.IsCA {
		return math("the TSL signer anchor is no CA")
	}
	if !bytes.Equal(signer.RawIssuer, anchor.RawSubject) {
		return math("the signer's issuer is not the TSL signer anchor")
	}
	if len(signer.AuthorityKeyId) == 0 || !bytes.Equal(signer.AuthorityKeyId, anchor.SubjectKeyId) {
		return &TSLError{"authoritykeyid_different", "TSLSIG-031", "the signer's AuthorityKeyIdentifier is not the anchor's SubjectKeyIdentifier"}
	}
	if signer.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return profile("the certificate is not signed with ecdsa-with-SHA256")
	}
	if err := verifySignedBy(signer, anchor); err != nil {
		return math("the signer's certificate signature: " + err.Error())
	}
	for _, cert := range []*x509.Certificate{signer, anchor} {
		if now.Unix() < cert.NotBefore.Unix() || now.Unix() > cert.NotAfter.Unix() {
			return &TSLError{"certificate_not_valid_time", "TSLSIG-032", fmt.Sprintf("%s is valid from %s to %s, not at %s", cert.Subject, cert.NotBefore, cert.NotAfter, now)}
		}
	}
	if signer.KeyUsage != x509.KeyUsageContentCommitment {
		return &TSLError{"wrong_keyusage", "TSLSIG-033", "KeyUsage is not exactly nonRepudiation"}
	}
	if usages := extKeyUsages(signer); len(usages) != 1 || !tslSigning.EqualASN1OID(usages[0]) {
		return &TSLError{"wrong_extendedkeyusage", "TSLSIG-034", "ExtendedKeyUsage is not exactly id-tsl-kp-tslSigning"}
	}
	if !containsOID(signer.Policies, oid.PolicyGemTSLSigner) {
		return profile("no oid_policy_gem_tsl_signer")
	}
	if signer.BasicConstraintsValid && signer.IsCA {
		return profile("a CA certificate")
	}
	if len(signer.OCSPServer) == 0 {
		return profile("no OCSP URL in AuthorityInfoAccess")
	}
	key, ok := signer.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != brainpool.P256r1() || !uncompressedPoint(signer) {
		return profile("the key is not an uncompressed brainpoolP256r1 point")
	}
	return nil
}

func uncompressedPoint(cert *x509.Certificate) bool {
	var spki struct {
		Algorithm asn1.RawValue
		Point     asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return false
	}
	return len(spki.Point.Bytes) == 65 && spki.Point.Bytes[0] == 0x04
}

// TSL is a parsed list.
type TSL struct {
	// ID is the root element's Id, which changes with every issue.
	ID             string
	SequenceNumber uint64
	IssuedAt       time.Time
	// NextUpdate is zero on a closed list.
	NextUpdate time.Time
	Services   []Service
	Scheme     SchemeInfo
	// Skipped counts the services left out because they could not be processed; only a verified
	// list may skip (TSLSIG-052).
	Skipped int
}

// SchemeInfo is what SchemeInformation says of the list and its operator, beyond number and dates.
type SchemeInfo struct {
	// VersionIdentifier is zero if the list states none that parses.
	VersionIdentifier   uint32
	TSLType             string
	SchemeName          string
	OperatorName        string
	PostalAddresses     []PostalAddress
	ElectronicAddresses []string
	Pointers            []TSLPointer
}

// PostalAddress is one of the operator's addresses.
type PostalAddress struct {
	Street, PostalCode, Locality, State, Country string
}

// TSLPointer is an entry of PointersToOtherTSL. It says where the list is published, and a list is
// never fetched from it (TSLSIG-050).
type TSLPointer struct {
	Location              string
	AdditionalInformation []string
}

// PrimaryLocation is the list's primary download point, or empty.
func (s SchemeInfo) PrimaryLocation() string { return s.locationMarked(primaryLocation) }

// BackupLocation is the list's backup download point, or empty.
func (s SchemeInfo) BackupLocation() string { return s.locationMarked(backupLocation) }

func (s SchemeInfo) locationMarked(marker string) string {
	for _, pointer := range s.Pointers {
		if slices.Contains(pointer.AdditionalInformation, marker) {
			return pointer.Location
		}
	}
	return ""
}

// Service is one trust service of a provider.
type Service struct {
	Provider           string
	Name               string
	ServiceType        string
	Status             string
	StatusStartingTime time.Time
	// Certificate is nil for a service without one, such as a CVC CA.
	Certificate *x509.Certificate
	// SupplyPoints are, for a CA, the OCSP responders of its certificates.
	SupplyPoints []string
	// TypeOIDs are, for a CA, the certificate types it may issue, without the placeholder.
	TypeOIDs []x509.OID
}

type xmlNames struct {
	Names []string `xml:"Name"`
}

type xmlList struct {
	XMLName xml.Name `xml:"TrustServiceStatusList"`
	ID      string   `xml:"Id,attr"`
	Scheme  *struct {
		SequenceNumber *string `xml:"TSLSequenceNumber"`
		IssuedAt       *string `xml:"ListIssueDateTime"`
		NextUpdate     *struct {
			DateTime *string `xml:"dateTime"`
		} `xml:"NextUpdate"`
		VersionIdentifier *string   `xml:"TSLVersionIdentifier"`
		TSLType           string    `xml:"TSLType"`
		SchemeName        *xmlNames `xml:"SchemeName"`
		OperatorName      *xmlNames `xml:"SchemeOperatorName"`
		Postal            []struct {
			Street     string `xml:"StreetAddress"`
			Locality   string `xml:"Locality"`
			State      string `xml:"StateOrProvince"`
			PostalCode string `xml:"PostalCode"`
			Country    string `xml:"CountryName"`
		} `xml:"SchemeOperatorAddress>PostalAddresses>PostalAddress"`
		Electronic []string `xml:"SchemeOperatorAddress>ElectronicAddress>URI"`
		Pointers   []struct {
			Location   string   `xml:"TSLLocation"`
			Additional []string `xml:"AdditionalInformation>TextualInformation"`
		} `xml:"PointersToOtherTSL>OtherTSLPointer"`
	} `xml:"SchemeInformation"`
	Providers []struct {
		Name     *xmlNames `xml:"TSPInformation>TSPName"`
		Services []struct {
			Name     *xmlNames `xml:"ServiceInformation>ServiceName"`
			Type     *string   `xml:"ServiceInformation>ServiceTypeIdentifier"`
			Status   *string   `xml:"ServiceInformation>ServiceStatus"`
			Start    *string   `xml:"ServiceInformation>StatusStartingTime"`
			Identity *struct {
				IDs []struct {
					Certificate *string `xml:"X509Certificate"`
				} `xml:"DigitalId"`
			} `xml:"ServiceInformation>ServiceDigitalIdentity"`
			Points []string  `xml:"ServiceInformation>ServiceSupplyPoints>ServiceSupplyPoint"`
			OIDs   []*string `xml:"ServiceInformation>ServiceInformationExtensions>Extension>ExtensionOID"`
		} `xml:"TSPServices>TSPService"`
	} `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

func firstName(names *xmlNames) string {
	if names == nil || len(names.Names) == 0 {
		return ""
	}
	return strings.TrimSpace(names.Names[0])
}

// parseTSL reads a list whose signature verified, so a service it cannot process is left out and
// counted (TSLSIG-052). encoding/xml expands no entities a document defines, and takes only UTF-8.
func parseTSL(data []byte) (*TSL, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("not UTF-8")
	}
	var list xmlList
	if err := xml.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list.Scheme == nil || list.Scheme.SequenceNumber == nil || list.Scheme.IssuedAt == nil {
		return nil, errors.New("no SchemeInformation with TSLSequenceNumber and ListIssueDateTime")
	}
	tsl := &TSL{ID: strings.TrimSpace(list.ID)}
	if _, err := fmt.Sscan(strings.TrimSpace(*list.Scheme.SequenceNumber), &tsl.SequenceNumber); err != nil {
		return nil, fmt.Errorf("TSLSequenceNumber: %w", err)
	}
	var err error
	if tsl.IssuedAt, err = parseTSLTime(*list.Scheme.IssuedAt, "ListIssueDateTime"); err != nil {
		return nil, err
	}
	if next := list.Scheme.NextUpdate; next != nil && next.DateTime != nil {
		if tsl.NextUpdate, err = parseTSLTime(*next.DateTime, "NextUpdate"); err != nil {
			return nil, err
		}
	}
	scheme := list.Scheme
	if scheme.VersionIdentifier != nil {
		var version uint32
		if _, err := fmt.Sscan(strings.TrimSpace(*scheme.VersionIdentifier), &version); err == nil {
			tsl.Scheme.VersionIdentifier = version
		}
	}
	tsl.Scheme.TSLType = strings.TrimSpace(scheme.TSLType)
	tsl.Scheme.SchemeName = firstName(scheme.SchemeName)
	tsl.Scheme.OperatorName = firstName(scheme.OperatorName)
	for _, a := range scheme.Postal {
		tsl.Scheme.PostalAddresses = append(tsl.Scheme.PostalAddresses, PostalAddress{
			Street: strings.TrimSpace(a.Street), PostalCode: strings.TrimSpace(a.PostalCode), Locality: strings.TrimSpace(a.Locality),
			State: strings.TrimSpace(a.State), Country: strings.TrimSpace(a.Country),
		})
	}
	for _, uri := range scheme.Electronic {
		tsl.Scheme.ElectronicAddresses = append(tsl.Scheme.ElectronicAddresses, strings.TrimSpace(uri))
	}
	for _, pointer := range scheme.Pointers {
		parsed := TSLPointer{Location: strings.TrimSpace(pointer.Location)}
		for _, text := range pointer.Additional {
			parsed.AdditionalInformation = append(parsed.AdditionalInformation, strings.TrimSpace(text))
		}
		tsl.Scheme.Pointers = append(tsl.Scheme.Pointers, parsed)
	}
	for _, provider := range list.Providers {
		providerName := firstName(provider.Name)
		for _, raw := range provider.Services {
			service, err := convertService(providerName, firstName(raw.Name), raw.Type, raw.Status, raw.Start, raw.Identity, raw.Points, raw.OIDs)
			if err != nil {
				tsl.Skipped++
				continue
			}
			tsl.Services = append(tsl.Services, service)
		}
	}
	return tsl, nil
}

func parseTSLTime(value, element string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q is not an RFC 3339 dateTime", element, value)
	}
	return parsed, nil
}

func convertService(provider, name string, serviceType, status, start *string, identity *struct {
	IDs []struct {
		Certificate *string `xml:"X509Certificate"`
	} `xml:"DigitalId"`
}, points []string, oids []*string,
) (Service, error) {
	service := Service{Provider: provider, Name: name}
	if serviceType == nil || status == nil || identity == nil {
		return service, fmt.Errorf("service %q lacks a required element", name)
	}
	service.ServiceType = strings.TrimSpace(*serviceType)
	service.Status = strings.TrimSpace(*status)
	for _, id := range identity.IDs {
		if id.Certificate == nil {
			continue
		}
		der, err := base64.StdEncoding.Strict().DecodeString(strings.Join(strings.Fields(*id.Certificate), ""))
		if err != nil {
			return service, fmt.Errorf("certificate of %q: %w", name, err)
		}
		if service.Certificate, err = ParseCertificate(der); err != nil {
			return service, fmt.Errorf("certificate of %q: %w", name, err)
		}
		break
	}
	if start != nil {
		var err error
		if service.StatusStartingTime, err = parseTSLTime(*start, "StatusStartingTime"); err != nil {
			return service, err
		}
	}
	for _, point := range points {
		service.SupplyPoints = append(service.SupplyPoints, strings.TrimSpace(point))
	}
	for _, raw := range oids {
		if raw == nil {
			continue
		}
		id, err := oid.Parse(strings.TrimSpace(*raw))
		if err != nil {
			return service, fmt.Errorf("ExtensionOID of %q: %w", name, err)
		}
		if !id.Equal(tslPlaceholder) {
			service.TypeOIDs = append(service.TypeOIDs, id)
		}
	}
	return service, nil
}

// Intermediate is a CA the list names, with the provider it is listed under. It is a candidate until
// [MatchToRoots] has kept it.
type Intermediate struct {
	Certificate *x509.Certificate
	Provider    string
	// RevokedSince is, for a revoked CA, when: end entities issued before it stay valid. Zero if the
	// CA is in accord.
	RevokedSince time.Time
}

// IntermediateCAs gives the CA services in accord, and the revoked ones with a time, in document order.
// A revoked CA without the time is left out, since nothing tells which of its certificates count.
func (t *TSL) IntermediateCAs() []Intermediate {
	var cas []Intermediate
	for _, service := range t.Services {
		if service.ServiceType != serviceTypeCAPKC || service.Certificate == nil {
			continue
		}
		candidate := Intermediate{Certificate: service.Certificate, Provider: service.Provider}
		switch service.Status {
		case serviceStatusInAccord, serviceStatusGranted:
		case serviceStatusRevoked:
			if service.StatusStartingTime.IsZero() {
				continue
			}
			candidate.RevokedSince = service.StatusStartingTime
		default:
			continue
		}
		cas = append(cas, candidate)
	}
	return cas
}

// The reasons [MatchToRoots] gives for not keeping a candidate.
const (
	RejectNotCA         = "not_ca"
	RejectSelfSigned    = "self_signed"
	RejectUnknownIssuer = "unknown_issuer"
	RejectBadSignature  = "bad_signature"
)

// Rejected is a candidate [MatchToRoots] did not keep.
type Rejected struct {
	Intermediate Intermediate
	Reason       string
}

// MatchToRoots keeps the candidates a root signed directly: the list is a directory, not a source of
// trust. A self-signed CA is not kept. Validity is left to [ValidatePath], which reports it precisely.
func MatchToRoots(candidates []Intermediate, roots []*x509.Certificate) (kept []Intermediate, rejected []Rejected) {
	for _, candidate := range candidates {
		if reason := checkCandidate(candidate.Certificate, roots); reason != "" {
			rejected = append(rejected, Rejected{candidate, reason})
			continue
		}
		kept = append(kept, candidate)
	}
	return kept, rejected
}

func checkCandidate(candidate *x509.Certificate, roots []*x509.Certificate) string {
	if !candidate.BasicConstraintsValid || !candidate.IsCA {
		return RejectNotCA
	}
	if bytes.Equal(candidate.RawSubject, candidate.RawIssuer) {
		return RejectSelfSigned
	}
	named := false
	for _, root := range roots {
		if !bytes.Equal(root.RawSubject, candidate.RawIssuer) {
			continue
		}
		named = true
		if verifySignedBy(candidate, root) == nil {
			return ""
		}
	}
	if named {
		return RejectBadSignature
	}
	return RejectUnknownIssuer
}

// MaxBundleAge is how old a bundle may be (BUNDLE-003), the production maximum of ti-pki's reloader.
const MaxBundleAge = 24 * time.Hour

// ListedResponder is an OCSP service a verified list names in accord, with its provider.
type ListedResponder struct {
	Certificate *x509.Certificate
	TSP         string
}

// TrustStore is what a bundle yields: the roots and the CAs a root signed, from a verified list.
type TrustStore struct {
	Roots         []*x509.Certificate
	Intermediates []Intermediate
	// ListedResponders authorize a responder beyond RFC 6960, whatever CA it answers for (OCSP-001).
	ListedResponders []ListedResponder
	// CATypes are the certificate types the verified list states for its CAs, by the CA's DER. Nil
	// without a verified list.
	CATypes map[string][]x509.OID
	// TSL is the verified list they come from, with its warnings.
	TSL *VerifiedTSL
	// Walk says where the roots walk stopped, if it did.
	Walk Walk
}

// LoadTrustStore builds the store a bundle yields at now, without a network (BUNDLE-003): a bundle too
// old is refused, the roots come from the walk from anchorDER, and the CAs from a list verified under
// signerAnchors, with the signer's status from the bundle if it holds a current one. Otherwise no_ocsp_check
// stays among the warnings, and the caller asks with [VerifiedTSL.CheckSignerStatus]: OCSP is not air-gapped,
// only the chain is. A server has a grace of zero. stored is the state of the list in use, nil if there is
// none, and an older list is refused against it (TSLSIG-053); the caller keeps [VerifiedTSL.State].
func LoadTrustStore(bundle *Bundle, anchorDER []byte, signerAnchors [][]byte, now time.Time, grace time.Duration, stored *TSLState) (*TrustStore, error) {
	if age := now.Sub(bundle.FetchedAt); age >= MaxBundleAge {
		return nil, fmt.Errorf("tipki: bundle %q is %s old, the limit is %s", bundle.Label, age.Round(time.Minute), MaxBundleAge)
	}
	walk, err := TrustedRoots(bundle, anchorDER, now)
	if err != nil {
		return nil, err
	}
	verified, err := VerifyTSL(bundle.TSL, bundle.TSLSignature, signerAnchors, now, grace)
	if err != nil {
		return nil, err
	}
	if _, err := verified.CheckSequence(stored); err != nil {
		return nil, err
	}
	kept, _ := MatchToRoots(verified.TSL.IntermediateCAs(), walk.Trusted)
	if bundle.TSLSignerStatus != nil {
		if _, err := verified.CheckSignerStatusSupplied(bundle.TSLSignerStatus, now); err != nil {
			return nil, err
		}
	}
	var listed []ListedResponder
	for _, service := range verified.TSL.Services {
		if service.ServiceType == serviceTypeOCSP && service.Certificate != nil &&
			(service.Status == serviceStatusInAccord || service.Status == serviceStatusGranted) {
			listed = append(listed, ListedResponder{service.Certificate, service.Provider})
		}
	}
	types := make(map[string][]x509.OID)
	for _, service := range verified.TSL.Services {
		if service.ServiceType == serviceTypeCAPKC && service.Certificate != nil {
			if _, seen := types[string(service.Certificate.Raw)]; !seen {
				types[string(service.Certificate.Raw)] = service.TypeOIDs
			}
		}
	}
	return &TrustStore{Roots: walk.Trusted, Intermediates: kept, ListedResponders: listed, CATypes: types, TSL: verified, Walk: walk}, nil
}

// tslTypesOf gives the types the list lets ca issue: nil if it does not list ca or states none for it.
func (s *TrustStore) tslTypesOf(ca *x509.Certificate) []x509.OID {
	types := s.CATypes[string(ca.Raw)]
	if len(types) == 0 {
		return nil
	}
	return types
}

// revokedSince says when the list revoked ca; zero if it did not.
func (s *TrustStore) revokedSince(ca *x509.Certificate) time.Time {
	for _, intermediate := range s.Intermediates {
		if intermediate.Certificate.Equal(ca) {
			return intermediate.RevokedSince
		}
	}
	return time.Time{}
}

func (s *TrustStore) providerOf(cert *x509.Certificate) (string, bool) {
	for _, intermediate := range s.Intermediates {
		if intermediate.Certificate.Equal(cert) {
			return intermediate.Provider, true
		}
	}
	return "", false
}

// Certificates gives the store's CAs as [BuildChain] takes them.
func (s *TrustStore) Certificates() []*x509.Certificate {
	certs := make([]*x509.Certificate, len(s.Intermediates))
	for i, intermediate := range s.Intermediates {
		certs[i] = intermediate.Certificate
	}
	return certs
}
