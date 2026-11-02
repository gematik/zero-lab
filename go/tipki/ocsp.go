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
	"context"
	"crypto/sha1" //nolint:gosec // RFC 5019's CertID hash: it only identifies, integrity rests on the signature.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

const (
	// DefaultClockTolerance is the skew TUC_PKI_006 grants a responder (gemSpec_PKI: 37.5 s).
	DefaultClockTolerance = 37500 * time.Millisecond
	// DefaultMaxResponseAge is how old producedAt may be. TI responders sign on demand.
	DefaultMaxResponseAge = DefaultClockTolerance
	// OCSPStatusRetries is how often a query is repeated after a status error (A_30044 (4)).
	OCSPStatusRetries = 3
	// OCSPStatusPause is how long a responder rests once the query and its repetitions failed.
	OCSPStatusPause = 300 * time.Second
	// OCSPCacheTTL is how long a good or revoked result is reused, at most until nextUpdate.
	OCSPCacheTTL = time.Hour
	// MaxSuppliedSignerStatusAge is how long a signer status in a bundle counts (TSLDET-021).
	MaxSuppliedSignerStatusAge = 2 * time.Hour

	contentTypeOCSPRequest  = "application/ocsp-request"
	contentTypeOCSPResponse = "application/ocsp-response"
	oidCertHash             = "1.3.36.8.3.13"
	oidOCSPBasic            = "1.3.6.1.5.5.7.48.1.1"
	oidOCSPSigning          = "1.3.6.1.5.5.7.3.9"
	serviceTypeOCSP         = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
	unknownStatusReason     = "OCSP status: unknown"
)

// RevocationStatus is what a source said about one certificate.
type RevocationStatus string

// The statuses.
const (
	RevocationGood    RevocationStatus = "good"
	RevocationRevoked RevocationStatus = "revoked"
	RevocationUnknown RevocationStatus = "unknown"
)

// ResponderAuthorization says why the signer of a response could answer.
type ResponderAuthorization struct {
	// Kind is issuer, delegate, tsl_listed or same_tsp_delegate; the last is no RFC 6960 conformance.
	Kind string
	// CA is the common name of the CA that certified the responder, for the last two kinds.
	CA string
	// TSP is the provider the TSL lists both under, for the last two kinds.
	TSP string
}

// RevocationResult is the outcome for one certificate.
type RevocationResult struct {
	Status    RevocationStatus
	CheckedAt time.Time
	// RevokedAt is zero unless revoked.
	RevokedAt time.Time
	// Reason is the revocation reason, or why the status is unknown.
	Reason       string
	ResponderURL string
	ProducedAt   time.Time
	ThisUpdate   time.Time
	// NextUpdate is zero if the responder set none.
	NextUpdate time.Time
	// Responder is the delegate's certificate; nil when the issuer signed itself.
	Responder     *x509.Certificate
	ResponderName string
	Authorization *ResponderAuthorization
	RawResponse   []byte
	FromCache     bool
}

// OCSPError says why a response gave no result. Code is ocsp_unavailable, ocsp_response_invalid or
// ocsp_responder_untrusted, as the revocation table in [ApplyRevocation] decides on them.
type OCSPError struct {
	Code    string
	Subject string
	Message string
	defect  responseDefect
	// unreachable says the responder could not be reached, rather than answering with an error.
	unreachable bool
}

func (e *OCSPError) Error() string { return e.Code + ": " + e.Message }

type responseDefect int

const (
	defectNone responseDefect = iota
	defectWrongCertificate
	defectSignature
	defectCertHashMissing
	defectCertHashMismatch
)

// ResponseCheck is what [VerifyResponse] checks against.
type ResponseCheck struct {
	// Now is the instant the time window is anchored at.
	Now time.Time
	// MaxResponseAge is how old producedAt may be.
	MaxResponseAge time.Duration
	// ClockTolerance is the skew allowed between the responder's clock and ours.
	ClockTolerance time.Duration
	// AllowMissingCertHash accepts a response without the extension. One present is checked anyway.
	AllowMissingCertHash bool
	// Store may authorize a delegate of another CA of the issuing CA's provider. Without it, only
	// RFC 6960 applies.
	Store *TrustStore
	// Stapled says the response came with the object: it must be valid at Now, without tolerance or
	// maximum age, and an eGK certificate needs no certHash (A_30046 (7)).
	Stapled bool
}

// NewResponseCheck is the strict check at now: the default window, certHash required.
func NewResponseCheck(now time.Time) ResponseCheck {
	return ResponseCheck{Now: now, MaxResponseAge: DefaultMaxResponseAge, ClockTolerance: DefaultClockTolerance}
}

func subjectPublicKeyBits(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, err
	}
	return spki.Key.Bytes, nil
}

// OCSPRequest is the DER request for cert, issued by issuer: one request with a SHA-1 CertID, unsigned
// and without a nonce. RFC 5019 prescribes the hash and TI responders reject others.
func OCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	key, err := subjectPublicKeyBits(issuer)
	if err != nil {
		return nil, fmt.Errorf("tipki: issuer key: %w", err)
	}
	name, keyHash := sha1.Sum(issuer.RawSubject), sha1.Sum(key) //nolint:gosec // See the import.
	type algorithm struct {
		ID     asn1.ObjectIdentifier
		Params asn1.RawValue
	}
	type certID struct {
		Hash     algorithm
		NameHash []byte
		KeyHash  []byte
		Serial   *big.Int
	}
	type request struct{ CertID certID }
	type tbs struct{ List []request }
	type outer struct{ TBS tbs }
	return asn1.Marshal(outer{tbs{[]request{{certID{
		Hash:     algorithm{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, asn1.NullRawValue},
		NameHash: name[:], KeyHash: keyHash[:], Serial: cert.SerialNumber,
	}}}}})
}

type singleResponse struct {
	hashOID    string
	nameHash   []byte
	keyHash    []byte
	serial     *big.Int
	statusTag  int
	revokedAt  time.Time
	reason     string
	thisUpdate time.Time
	nextUpdate time.Time
	extensions []asn1.RawValue
}

type basicResponse struct {
	tbs          []byte
	sigAlgorithm []byte
	signature    []byte
	certs        []*x509.Certificate
	responderID  asn1.RawValue
	producedAt   time.Time
	responses    []singleResponse
}

func undecodable(detail string) *OCSPError {
	return &OCSPError{Code: "ocsp_unavailable", Message: "OCSP response could not be decoded: " + detail}
}

// responseStatus reads the outer OCSPResponse: its status, and the BasicOCSPResponse bytes if any.
func parseOuterResponse(der []byte) (status int, bytesType string, body []byte, err error) {
	outer, err := element(der)
	if err != nil || !isSequence(outer) {
		return 0, "", nil, errors.New("not an OCSPResponse")
	}
	fields, err := elements(outer.Bytes)
	if err != nil || len(fields) == 0 || len(fields) > 2 {
		return 0, "", nil, errors.New("not an OCSPResponse")
	}
	var enumerated asn1.Enumerated
	if _, err := asn1.Unmarshal(fields[0].FullBytes, &enumerated); err != nil {
		return 0, "", nil, errors.New("no response status")
	}
	status = int(enumerated)
	if status != 0 && status != 1 && status != 2 && status != 3 && status != 5 && status != 6 {
		return 0, "", nil, errors.New("an unknown response status")
	}
	if len(fields) == 1 {
		return status, "", nil, nil
	}
	if fields[1].Class != asn1.ClassContextSpecific || fields[1].Tag != 0 || !fields[1].IsCompound {
		return 0, "", nil, errors.New("not an OCSPResponse")
	}
	inner, err := element(fields[1].Bytes)
	if err != nil || !isSequence(inner) {
		return 0, "", nil, errors.New("no responseBytes")
	}
	parts, err := elements(inner.Bytes)
	if err != nil || len(parts) != 2 || !isUniversal(parts[1], asn1.TagOctetString) {
		return 0, "", nil, errors.New("no responseBytes")
	}
	var id asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(parts[0].FullBytes, &id); err != nil {
		return 0, "", nil, errors.New("no response type")
	}
	return status, id.String(), parts[1].Bytes, nil
}

func parseGeneralizedTime(value asn1.RawValue) (time.Time, error) {
	if !isUniversal(value, asn1.TagGeneralizedTime) || len(value.Bytes) < 15 {
		return time.Time{}, errors.New("not a GeneralizedTime")
	}
	text := string(value.Bytes)
	if strings.Trim(text[:14], "0123456789") != "" {
		return time.Time{}, errors.New("not a GeneralizedTime")
	}
	rest := text[14:]
	if rest != "Z" {
		digits, ok := strings.CutPrefix(rest, ".")
		if ok {
			digits, ok = strings.CutSuffix(digits, "Z")
		}
		if !ok || digits == "" || strings.Trim(digits, "0123456789") != "" {
			return time.Time{}, errors.New("not a GeneralizedTime")
		}
	}
	return time.Parse("20060102150405", text[:14])
}

func parseBasicResponse(der []byte) (*basicResponse, error) {
	outer, err := element(der)
	if err != nil || !isSequence(outer) {
		return nil, errors.New("not a BasicOCSPResponse")
	}
	fields, err := elements(outer.Bytes)
	if err != nil || len(fields) < 3 || len(fields) > 4 || !isSequence(fields[0]) || !isSequence(fields[1]) ||
		fields[2].Class != asn1.ClassUniversal || fields[2].Tag != asn1.TagBitString {
		return nil, errors.New("not a BasicOCSPResponse")
	}
	if len(fields[2].Bytes) == 0 || fields[2].Bytes[0] != 0 {
		return nil, errors.New("a signature with unused bits")
	}
	basic := &basicResponse{tbs: fields[0].FullBytes, sigAlgorithm: fields[1].Bytes, signature: fields[2].Bytes[1:]}
	if len(fields) == 4 {
		if fields[3].Class != asn1.ClassContextSpecific || fields[3].Tag != 0 || !fields[3].IsCompound {
			return nil, errors.New("not a BasicOCSPResponse")
		}
		list, err := element(fields[3].Bytes)
		if err != nil || !isSequence(list) {
			return nil, errors.New("no certificate list")
		}
		raw, err := elements(list.Bytes)
		if err != nil {
			return nil, err
		}
		for _, one := range raw {
			cert, err := ParseCertificate(one.FullBytes)
			if err != nil {
				return nil, &OCSPError{Code: "ocsp_unavailable", Message: "OCSP response embeds an unparsable certificate"}
			}
			basic.certs = append(basic.certs, cert)
		}
	}
	data, err := elements(fields[0].Bytes)
	if err != nil {
		return nil, err
	}
	data = skipTagged(data, 0)
	if len(data) < 3 || len(data) > 4 {
		return nil, errors.New("not a ResponseData")
	}
	basic.responderID = data[0]
	if basic.producedAt, err = parseGeneralizedTime(data[1]); err != nil {
		return nil, err
	}
	if !isSequence(data[2]) {
		return nil, errors.New("no responses")
	}
	if len(data) == 4 && (data[3].Class != asn1.ClassContextSpecific || data[3].Tag != 1) {
		return nil, errors.New("not a ResponseData")
	}
	singles, err := elements(data[2].Bytes)
	if err != nil {
		return nil, err
	}
	for _, raw := range singles {
		single, err := parseSingleResponse(raw)
		if err != nil {
			return nil, err
		}
		basic.responses = append(basic.responses, single)
	}
	return basic, nil
}

var crlReasons = map[int]string{
	0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
	5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise",
}

func parseSingleResponse(raw asn1.RawValue) (singleResponse, error) {
	var single singleResponse
	if !isSequence(raw) {
		return single, errors.New("not a SingleResponse")
	}
	fields, err := elements(raw.Bytes)
	if err != nil || len(fields) < 3 || !isSequence(fields[0]) {
		return single, errors.New("not a SingleResponse")
	}
	id, err := elements(fields[0].Bytes)
	if err != nil || len(id) != 4 || !isSequence(id[0]) || !isUniversal(id[1], asn1.TagOctetString) || !isUniversal(id[2], asn1.TagOctetString) {
		return single, errors.New("not a CertID")
	}
	algorithm, err := elements(id[0].Bytes)
	if err != nil || len(algorithm) == 0 {
		return single, errors.New("not a CertID")
	}
	var hashOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(algorithm[0].FullBytes, &hashOID); err != nil {
		return single, errors.New("not a CertID")
	}
	single.hashOID, single.nameHash, single.keyHash = hashOID.String(), id[1].Bytes, id[2].Bytes
	if _, err := asn1.Unmarshal(id[3].FullBytes, &single.serial); err != nil {
		return single, errors.New("not a CertID")
	}
	status := fields[1]
	if status.Class != asn1.ClassContextSpecific {
		return single, errors.New("no certStatus")
	}
	single.statusTag = status.Tag
	switch status.Tag {
	case 0, 2:
		if status.IsCompound || len(status.Bytes) != 0 {
			return single, errors.New("no certStatus")
		}
	case 1:
		if !status.IsCompound {
			return single, errors.New("no certStatus")
		}
		info, err := elements(status.Bytes)
		if err != nil || len(info) == 0 || len(info) > 2 {
			return single, errors.New("no RevokedInfo")
		}
		if single.revokedAt, err = parseGeneralizedTime(info[0]); err != nil {
			return single, err
		}
		single.reason = "unspecified"
		if len(info) == 2 {
			if info[1].Class != asn1.ClassContextSpecific || info[1].Tag != 0 || !info[1].IsCompound {
				return single, errors.New("no RevokedInfo")
			}
			var reason asn1.Enumerated
			rest, err := asn1.Unmarshal(info[1].Bytes, &reason)
			name, ok := crlReasons[int(reason)]
			if err != nil || len(rest) != 0 || !ok {
				return single, errors.New("no RevokedInfo")
			}
			single.reason = name
		}
	default:
		return single, errors.New("no certStatus")
	}
	if single.thisUpdate, err = parseGeneralizedTime(fields[2]); err != nil {
		return single, err
	}
	rest := fields[3:]
	if len(rest) > 0 && rest[0].Class == asn1.ClassContextSpecific && rest[0].Tag == 0 {
		next, err := element(rest[0].Bytes)
		if err != nil {
			return single, err
		}
		if single.nextUpdate, err = parseGeneralizedTime(next); err != nil {
			return single, err
		}
		rest = rest[1:]
	}
	if len(rest) > 0 && rest[0].Class == asn1.ClassContextSpecific && rest[0].Tag == 1 {
		list, err := element(rest[0].Bytes)
		if err != nil || !isSequence(list) {
			return single, errors.New("no extensions")
		}
		if single.extensions, err = elements(list.Bytes); err != nil {
			return single, err
		}
		for _, extension := range single.extensions {
			if !validExtension(extension) {
				return single, errors.New("no extensions")
			}
		}
		rest = rest[1:]
	}
	if len(rest) != 0 {
		return single, errors.New("not a SingleResponse")
	}
	return single, nil
}

// validExtension checks an Extension's shape while the response is read, as a certHash that cannot be read
// is a response that cannot be read.
func validExtension(extension asn1.RawValue) bool {
	if !isSequence(extension) {
		return false
	}
	parts, err := elements(extension.Bytes)
	if err != nil || len(parts) < 2 || len(parts) > 3 || !isUniversal(parts[len(parts)-1], asn1.TagOctetString) {
		return false
	}
	var id asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(parts[0].FullBytes, &id); err != nil {
		return false
	}
	return len(parts) == 2 || isUniversal(parts[1], asn1.TagBoolean)
}

func digestFor(hashOID string, data []byte) []byte {
	switch hashOID {
	case "1.3.14.3.2.26":
		sum := sha1.Sum(data) //nolint:gosec // See the import.
		return sum[:]
	case "2.16.840.1.101.3.4.2.1":
		sum := sha256.Sum256(data)
		return sum[:]
	case "2.16.840.1.101.3.4.2.2":
		sum := sha512.Sum384(data)
		return sum[:]
	case "2.16.840.1.101.3.4.2.3":
		sum := sha512.Sum512(data)
		return sum[:]
	}
	return nil
}

func certIDMatches(single *singleResponse, cert, issuer *x509.Certificate) string {
	if single.serial.Cmp(cert.SerialNumber) != 0 {
		return "serial number differs"
	}
	name := digestFor(single.hashOID, issuer.RawSubject)
	if name == nil {
		return "unsupported CertID hash algorithm " + single.hashOID
	}
	if !bytes.Equal(name, single.nameHash) {
		return "issuerNameHash does not match the issuer"
	}
	key, err := subjectPublicKeyBits(issuer)
	if err != nil || !bytes.Equal(digestFor(single.hashOID, key), single.keyHash) {
		return "issuerKeyHash does not match the issuer's key"
	}
	return ""
}

// VerifyResponse decides what the DER response says about cert, issued by issuer. A response counts only
// if a single response carries the certificate's CertID, an authorized responder signed it, its certHash
// hashes this very certificate, and it lies within the TUC_PKI_006 window; outside the window the status
// is unknown. An error is an *[OCSPError]. ResponderURL is left for the caller.
func VerifyResponse(der []byte, cert, issuer *x509.Certificate, check ResponseCheck) (*RevocationResult, error) {
	result, err := verifyResponse(der, cert, issuer, check)
	if err != nil {
		err.Subject = cert.Subject.CommonName
		return nil, err
	}
	return result, nil
}

func verifyResponse(der []byte, cert, issuer *x509.Certificate, check ResponseCheck) (*RevocationResult, *OCSPError) {
	status, responseType, body, err := parseOuterResponse(der)
	if err != nil {
		return nil, undecodable(err.Error())
	}
	if status != 0 {
		return nil, &OCSPError{Code: "ocsp_unavailable", Message: fmt.Sprintf("OCSP responder answered status %d", status)}
	}
	if body == nil {
		return nil, &OCSPError{Code: "ocsp_unavailable", Message: "OCSP response is successful but carries no response"}
	}
	if responseType != oidOCSPBasic {
		return nil, &OCSPError{Code: "ocsp_unavailable", Message: "OCSP response type " + responseType + " is not id-pkix-ocsp-basic"}
	}
	basic, err := parseBasicResponse(body)
	if err != nil {
		if ocspError, ok := errors.AsType[*OCSPError](err); ok {
			return nil, ocspError
		}
		return nil, undecodable(err.Error())
	}
	index := slices.IndexFunc(basic.responses, func(single singleResponse) bool {
		return certIDMatches(&single, cert, issuer) == ""
	})
	if index < 0 {
		reason := "the response holds no single response"
		if len(basic.responses) > 0 {
			reason = certIDMatches(&basic.responses[0], cert, issuer)
		}
		return nil, &OCSPError{Code: "ocsp_response_invalid", defect: defectWrongCertificate,
			Message: "OCSP response does not answer for this certificate: " + reason}
	}
	single := &basic.responses[index]

	responder := pickResponder(basic.responderID, basic.certs)
	authorization := &ResponderAuthorization{Kind: "issuer"}
	signer := issuer
	if responder != nil {
		signer = responder
		if authorization, err = authorizeResponder(responder, issuer, check); err != nil {
			return nil, &OCSPError{Code: "ocsp_responder_untrusted", Message: err.Error()}
		}
	}
	algorithm, ok := signatureAlgorithmFromID(basic.sigAlgorithm)
	if !ok {
		return nil, &OCSPError{Code: "ocsp_response_invalid", defect: defectSignature,
			Message: fmt.Sprintf("OCSP response signature does not verify under %q: no admitted algorithm", signer.Subject.CommonName)}
	}
	if err := verifySignature(signer.PublicKey, algorithm, basic.tbs, basic.signature); err != nil {
		return nil, &OCSPError{Code: "ocsp_response_invalid", defect: defectSignature,
			Message: fmt.Sprintf("OCSP response signature does not verify under %q: %v", signer.Subject.CommonName, err)}
	}
	// An unknown answer has no certificate to vouch for, so it carries no certHash (A_30046 (2)).
	if single.statusTag != 2 {
		if failure := verifyCertHash(single.extensions, cert, check.AllowMissingCertHash || (check.Stapled && isEGK(cert))); failure != nil {
			return nil, failure
		}
	}
	result := &RevocationResult{
		Status: RevocationUnknown, CheckedAt: check.Now, ProducedAt: basic.producedAt, ThisUpdate: single.thisUpdate,
		NextUpdate: single.nextUpdate, Responder: responder, ResponderName: signer.Subject.CommonName,
		Authorization: authorization, RawResponse: der,
	}
	if reason := outsideWindow(result, check); reason != "" {
		result.Reason = reason
		return result, nil
	}
	switch single.statusTag {
	case 0:
		result.Status = RevocationGood
	case 1:
		result.Status, result.RevokedAt, result.Reason = RevocationRevoked, single.revokedAt, single.reason
	default:
		result.Reason = unknownStatusReason
	}
	return result, nil
}

// pickResponder finds the embedded certificate the responder ID names, by name or by the SHA-1 of its key,
// else the first; the authorization and signature checks decide either way.
func pickResponder(id asn1.RawValue, embedded []*x509.Certificate) *x509.Certificate {
	if id.Class == asn1.ClassContextSpecific && id.IsCompound {
		for _, cert := range embedded {
			switch id.Tag {
			case 1:
				if bytes.Equal(cert.RawSubject, id.Bytes) {
					return cert
				}
			case 2:
				var hash []byte
				key, err := subjectPublicKeyBits(cert)
				if _, parseErr := asn1.Unmarshal(id.Bytes, &hash); parseErr == nil && err == nil {
					sum := sha1.Sum(key) //nolint:gosec // See the import.
					if bytes.Equal(sum[:], hash) {
						return cert
					}
				}
			}
		}
	}
	if len(embedded) > 0 {
		return embedded[0]
	}
	return nil
}

func authorizeResponder(responder, issuer *x509.Certificate, check ResponseCheck) (*ResponderAuthorization, error) {
	responderKey, _ := subjectPublicKeyBits(responder)
	issuerKey, _ := subjectPublicKeyBits(issuer)
	if bytes.Equal(responder.RawSubject, issuer.RawSubject) && bytes.Equal(responderKey, issuerKey) {
		return &ResponderAuthorization{Kind: "issuer"}, nil
	}
	name, ca := responder.Subject.CommonName, issuer.Subject.CommonName
	if bytes.Equal(responder.RawIssuer, issuer.RawSubject) {
		if err := verifySignedBy(responder, issuer); err != nil {
			return nil, fmt.Errorf("OCSP responder %q names the issuing CA %q as its issuer, but its certificate does not verify under the CA's key: %w", name, ca, err)
		}
		if reason := delegateUnusable(responder, check); reason != "" {
			return nil, fmt.Errorf("OCSP responder %q, certified by the issuing CA %q, %s", name, ca, reason)
		}
		return &ResponderAuthorization{Kind: "delegate"}, nil
	}
	notRFC6960 := fmt.Sprintf("OCSP responder %q was certified by %q, but the certificate was issued by %q; RFC 6960 accepts only the issuing CA or a responder it certified directly", name, responder.Issuer.CommonName, ca)
	if check.Store == nil {
		return nil, fmt.Errorf("%s, and no trust store is at hand to accept a delegate of the same TSP", notRFC6960)
	}
	responderCA, tsp, reason := sameTSPDelegate(responder, issuer, check)
	if reason != "" {
		return nil, fmt.Errorf("%s; nor is it a delegate of the same TSP: %s", notRFC6960, reason)
	}
	kind := "same_tsp_delegate"
	if slices.ContainsFunc(check.Store.ListedResponders, func(listed ListedResponder) bool {
		return listed.TSP == tsp && listed.Certificate.Equal(responder)
	}) {
		kind = "tsl_listed"
	}
	return &ResponderAuthorization{Kind: kind, CA: responderCA, TSP: tsp}, nil
}

func delegateUnusable(responder *x509.Certificate, check ResponseCheck) string {
	if !slices.Contains(extKeyUsages(responder), oidOCSPSigning) {
		return "lacks id-kp-OCSPSigning"
	}
	skew := int64(check.ClockTolerance / time.Second)
	validAt := func(at int64) bool { return at >= responder.NotBefore.Unix() && at <= responder.NotAfter.Unix() }
	if !validAt(check.Now.Unix()+skew) && !validAt(check.Now.Unix()-skew) {
		return fmt.Sprintf("is not valid at %s (valid %s to %s)", check.Now.UTC().Format(time.RFC3339), responder.NotBefore.UTC().Format(time.RFC3339), responder.NotAfter.UTC().Format(time.RFC3339))
	}
	return ""
}

func sameTSPDelegate(responder, issuer *x509.Certificate, check ResponseCheck) (string, string, string) {
	if reason := delegateUnusable(responder, check); reason != "" {
		return "", "", "it " + reason
	}
	store := check.Store
	var responderCA *Intermediate
	for i := range store.Intermediates {
		ca := &store.Intermediates[i]
		if bytes.Equal(ca.Certificate.RawSubject, responder.RawIssuer) && verifySignedBy(responder, ca.Certificate) == nil {
			responderCA = ca
			break
		}
	}
	if responderCA == nil {
		return "", "", fmt.Sprintf("%q is not a TSL CA under the trusted roots whose signature on it verifies", responder.Issuer.CommonName)
	}
	issuerTSP, ok := store.providerOf(issuer)
	if !ok {
		return "", "", fmt.Sprintf("the issuing CA %q is not a TSL CA", issuer.Subject.CommonName)
	}
	if responderCA.Provider != issuerTSP {
		return "", "", fmt.Sprintf("%q belongs to TSP %q, the issuing CA to %q", responderCA.Certificate.Subject.CommonName, responderCA.Provider, issuerTSP)
	}
	return responderCA.Certificate.Subject.CommonName, issuerTSP, ""
}

func verifyCertHash(extensions []asn1.RawValue, cert *x509.Certificate, allowMissing bool) *OCSPError {
	mismatch := func(message string) *OCSPError {
		return &OCSPError{Code: "ocsp_response_invalid", defect: defectCertHashMismatch, Message: message}
	}
	for _, extension := range extensions {
		parts, err := elements(extension.Bytes)
		if err != nil || len(parts) < 2 {
			continue
		}
		var id asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(parts[0].FullBytes, &id); err != nil || id.String() != oidCertHash {
			continue
		}
		value := parts[len(parts)-1]
		if !isUniversal(value, asn1.TagOctetString) {
			return mismatch("OCSP certHash extension is malformed")
		}
		outer, err := element(value.Bytes)
		if err != nil || !isSequence(outer) {
			return mismatch("OCSP certHash extension is malformed")
		}
		fields, err := elements(outer.Bytes)
		if err != nil || len(fields) != 2 || !isSequence(fields[0]) || !isUniversal(fields[1], asn1.TagOctetString) {
			return mismatch("OCSP certHash extension is malformed")
		}
		algorithm, err := elements(fields[0].Bytes)
		if err != nil || len(algorithm) == 0 {
			return mismatch("OCSP certHash extension is malformed")
		}
		var hashOID asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(algorithm[0].FullBytes, &hashOID); err != nil {
			return mismatch("OCSP certHash extension is malformed")
		}
		expected := digestFor(hashOID.String(), cert.Raw)
		if expected == nil {
			return mismatch("OCSP certHash uses unsupported hash algorithm " + hashOID.String())
		}
		if !bytes.Equal(expected, fields[1].Bytes) {
			return mismatch("OCSP certHash does not match the certificate")
		}
		return nil
	}
	if allowMissing {
		return nil
	}
	return &OCSPError{Code: "ocsp_response_invalid", defect: defectCertHashMissing, Message: "OCSP response carries no certHash extension"}
}

// outsideWindow is the TUC_PKI_006 window: producedAt within [now - max age, now + tolerance], thisUpdate at
// most the tolerance in the future, nextUpdate at most the tolerance in the past.
func outsideWindow(result *RevocationResult, check ResponseCheck) string {
	format := func(t time.Time) string { return t.UTC().Format(time.RFC3339) }
	now := check.Now.Truncate(time.Second)
	if check.Stapled {
		if result.ThisUpdate.After(now) {
			return fmt.Sprintf("OCSP thisUpdate %s lies after the reference time %s", format(result.ThisUpdate), format(now))
		}
		if !result.NextUpdate.IsZero() && result.NextUpdate.Before(now) {
			return fmt.Sprintf("OCSP nextUpdate %s lies before the reference time %s", format(result.NextUpdate), format(now))
		}
		return ""
	}
	seconds := func(d time.Duration) int64 { return int64(d / time.Second) }
	if age := now.Sub(result.ProducedAt); age > check.MaxResponseAge {
		return fmt.Sprintf("OCSP response is %d s old, more than the %d s allowed", seconds(age), seconds(check.MaxResponseAge))
	}
	if ahead := result.ProducedAt.Sub(now); ahead > check.ClockTolerance {
		return fmt.Sprintf("OCSP producedAt lies %d s in the future", seconds(ahead))
	}
	if ahead := result.ThisUpdate.Sub(now); ahead > check.ClockTolerance {
		return fmt.Sprintf("OCSP thisUpdate lies %d s in the future", seconds(ahead))
	}
	if !result.NextUpdate.IsZero() {
		if past := now.Sub(result.NextUpdate); past > check.ClockTolerance {
			return fmt.Sprintf("OCSP nextUpdate passed %d s ago", seconds(past))
		}
	}
	return ""
}

func isEGK(cert *x509.Certificate) bool {
	if t, ok := DetectCertificateType(cert); ok {
		switch t {
		case CertChQes, CertChSig, CertChEnc, CertChEncv, CertChAut, CertChAutn:
			return true
		}
	}
	admission, err := Admission(cert)
	return err == nil && slices.Contains(admission.ProfessionOIDs, oid.ProfVersicherter)
}

// RevocationChecker answers revocation questions. store is the trust store the chain was built against,
// nil if none, which leaves only RFC 6960 authorization.
type RevocationChecker interface {
	Check(ctx context.Context, cert, issuer *x509.Certificate, store *TrustStore) (*RevocationResult, error)
}

// OCSPTransport is the host's HTTP: it owns timeouts, proxies and whether a responder is reachable at all.
type OCSPTransport interface {
	Post(ctx context.Context, url, contentType, accept string, body []byte) ([]byte, error)
}

// OCSPChecker queries a certificate's responder through a transport and verifies the answer. A status error,
// which is a failed transport or an answer other than successful, is repeated [OCSPStatusRetries] times;
// after that the responder rests for [OCSPStatusPause]. Good and revoked results are reused for CacheTTL, at
// most until the response's nextUpdate; unknown and errors never are. Results live in memory only.
type OCSPChecker struct {
	Transport OCSPTransport
	// Now is the clock.
	Now func() time.Time
	// ClockTolerance and MaxResponseAge are those of [ResponseCheck].
	ClockTolerance time.Duration
	MaxResponseAge time.Duration
	// CacheTTL of zero turns the cache off.
	CacheTTL time.Duration
	// ResponderURL sends every request there instead of the certificate's own responder.
	ResponderURL string
	// AllowMissingCertHash is for responders outside the TI.
	AllowMissingCertHash bool

	mu      sync.Mutex
	resting map[string]time.Time
	cache   map[string]cachedResult
}

type cachedResult struct {
	result RevocationResult
	until  time.Time
}

// NewOCSPChecker is a strict checker asking the responder named in each certificate.
func NewOCSPChecker(transport OCSPTransport) *OCSPChecker {
	return &OCSPChecker{
		Transport: transport, Now: time.Now, ClockTolerance: DefaultClockTolerance,
		MaxResponseAge: DefaultMaxResponseAge, CacheTTL: OCSPCacheTTL,
	}
}

// Check implements [RevocationChecker]. A certificate without a responder is unknown, since no other source
// could answer for it either. An error that outlasts the repetitions, and any query while the responder
// rests, is ocsp_unavailable.
func (c *OCSPChecker) Check(ctx context.Context, cert, issuer *x509.Certificate, store *TrustStore) (*RevocationResult, error) {
	url := c.ResponderURL
	if url == "" && len(cert.OCSPServer) > 0 {
		url = cert.OCSPServer[0]
	}
	if url == "" {
		return &RevocationResult{Status: RevocationUnknown, CheckedAt: c.Now(), Reason: "no OCSP responder URL (no authority information access, no override)"}, nil
	}
	body, err := OCSPRequest(cert, issuer)
	if err != nil {
		return nil, &OCSPError{Code: "ocsp_unavailable", Subject: cert.Subject.CommonName, Message: err.Error()}
	}
	now := c.Now()
	if cached := c.cached(string(body), now); cached != nil {
		return cached, nil
	}
	if until, ok := c.restingUntil(url, now); ok {
		return nil, &OCSPError{Code: "ocsp_unavailable", Subject: cert.Subject.CommonName,
			Message: fmt.Sprintf("OCSP responder %s rests until %s after repeated failures", url, until.UTC().Format(time.RFC3339))}
	}
	response, failure := c.query(ctx, url, body, cert)
	if failure != nil {
		return nil, failure
	}
	check := ResponseCheck{
		Now: c.Now(), MaxResponseAge: c.MaxResponseAge, ClockTolerance: c.ClockTolerance,
		AllowMissingCertHash: c.AllowMissingCertHash, Store: store,
	}
	result, err := VerifyResponse(response, cert, issuer, check)
	if err != nil {
		return nil, err
	}
	result.ResponderURL = url
	if until, ok := c.reusableUntil(result, check.Now); ok {
		c.mu.Lock()
		if c.cache == nil {
			c.cache = make(map[string]cachedResult)
		}
		c.cache[string(body)] = cachedResult{*result, until}
		c.mu.Unlock()
	}
	return result, nil
}

func (c *OCSPChecker) cached(key string, now time.Time) *RevocationResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[key]
	if !ok {
		return nil
	}
	if !entry.until.After(now) {
		delete(c.cache, key)
		return nil
	}
	result := entry.result
	result.FromCache = true
	return &result
}

func (c *OCSPChecker) reusableUntil(result *RevocationResult, now time.Time) (time.Time, bool) {
	if c.CacheTTL <= 0 || (result.Status != RevocationGood && result.Status != RevocationRevoked) {
		return time.Time{}, false
	}
	until := now.Add(c.CacheTTL)
	if !result.NextUpdate.IsZero() && result.NextUpdate.Before(until) {
		until = result.NextUpdate
	}
	return until, until.After(now)
}

func (c *OCSPChecker) restingUntil(url string, now time.Time) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.resting[url]
	if !ok {
		return time.Time{}, false
	}
	if !until.After(now) {
		delete(c.resting, url)
		return time.Time{}, false
	}
	return until, true
}

// query POSTs until an answer is successful. A call the caller gave up on is no fault of the responder, so
// it neither repeats nor sends the responder to rest.
func (c *OCSPChecker) query(ctx context.Context, url string, body []byte, cert *x509.Certificate) ([]byte, *OCSPError) {
	var failure *OCSPError
	for range OCSPStatusRetries + 1 {
		answer, err := c.Transport.Post(ctx, url, contentTypeOCSPRequest, contentTypeOCSPResponse, body)
		if ctx.Err() != nil {
			return nil, &OCSPError{Code: "ocsp_unavailable", Subject: cert.Subject.CommonName, Message: ctx.Err().Error(), unreachable: true}
		}
		switch {
		case err != nil:
			failure = &OCSPError{Code: "ocsp_unavailable", Message: fmt.Sprintf("OCSP responder %s unreachable: %v", url, err), unreachable: true}
		default:
			status, _, _, parseErr := parseOuterResponse(answer)
			if parseErr == nil && status == 0 {
				return answer, nil
			}
			if parseErr != nil {
				failure = &OCSPError{Code: "ocsp_unavailable", Message: fmt.Sprintf("OCSP responder %s sent no OCSP response", url)}
			} else {
				failure = &OCSPError{Code: "ocsp_unavailable", Message: fmt.Sprintf("OCSP responder %s answered status %d", url, status)}
			}
		}
	}
	until := c.Now().Add(OCSPStatusPause)
	c.mu.Lock()
	if c.resting == nil {
		c.resting = make(map[string]time.Time)
	}
	c.resting[url] = until
	c.mu.Unlock()
	failure.Message = fmt.Sprintf("%s (%d attempts; resting until %s)", failure.Message, OCSPStatusRetries+1, until.UTC().Format(time.RFC3339))
	failure.Subject = cert.Subject.CommonName
	return nil, failure
}

// RevocationFinding is what [ApplyRevocation] makes of an outcome.
type RevocationFinding struct {
	Finding Finding
	// Warning says the certificate is accepted all the same.
	Warning bool
}

// ApplyRevocation maps a checker's outcome for a certificate validated for the reference time at, onto a
// finding; nil means nothing to report. It is the one place the mode is interpreted:
//
//	outcome                          hard-fail  soft-fail
//	good                             -          -
//	revoked at or before at          error      error
//	revoked after at                 warning    warning
//	unknown, responder unavailable   error      warning
//	responder untrusted, invalid     error      error
func ApplyRevocation(mode RevocationMode, subject string, result *RevocationResult, failure error, at time.Time) *RevocationFinding {
	if mode == RevocationDisabled {
		return nil
	}
	soft := mode == RevocationSoftFail
	if failure != nil {
		code, message, name := "ocsp_unavailable", failure.Error(), subject
		if ocspError, ok := errors.AsType[*OCSPError](failure); ok {
			code, message = ocspError.Code, ocspError.Message
			if ocspError.Subject != "" {
				name = ocspError.Subject
			}
		}
		untrusted := code == "ocsp_responder_untrusted" || code == "ocsp_response_invalid"
		return &RevocationFinding{Finding{code, name, message}, soft && !untrusted}
	}
	switch result.Status {
	case RevocationGood:
		return nil
	case RevocationRevoked:
		when := "an unknown time"
		if !result.RevokedAt.IsZero() {
			when = result.RevokedAt.UTC().Format(time.RFC3339)
			if result.RevokedAt.Unix() > at.Unix() {
				return &RevocationFinding{Finding{"revoked_after_reference_time", subject,
					fmt.Sprintf("certificate revoked at %s, after the reference time: %s", when, result.Reason)}, true}
			}
		}
		return &RevocationFinding{Finding{"revoked", subject, fmt.Sprintf("certificate revoked at %s: %s", when, result.Reason)}, false}
	}
	return &RevocationFinding{Finding{"ocsp_unavailable", subject, "revocation status unknown: " + result.Reason}, soft}
}

// CheckSignerStatus asks checker for the signer's status (TSLSIG-040 to 042), with the TSL signer CA as
// issuer and no store, so only that CA or a responder it certified may answer. Good removes the no_ocsp_check
// warning; anything else is an error and the list must not be used.
func (v *VerifiedTSL) CheckSignerStatus(ctx context.Context, checker RevocationChecker) error {
	result, err := checker.Check(ctx, v.Signer, v.Anchor, nil)
	if err != nil {
		return statusError(err)
	}
	return v.adoptSignerStatus(result, result.ResponderURL)
}

// CheckSignerStatusSupplied takes the signer's status from a response in the bundle (TSLDET-020, 021). True
// once adopted. False if it is older than [MaxSuppliedSignerStatusAge], which leaves the status unqueried
// for a network query to replace. A signed revoked stays true whatever its age, so that is still an error.
func (v *VerifiedTSL) CheckSignerStatusSupplied(response []byte, now time.Time) (bool, error) {
	check := NewResponseCheck(now)
	check.MaxResponseAge = MaxSuppliedSignerStatusAge
	result, err := VerifyResponse(response, v.Signer, v.Anchor, check)
	if err != nil {
		return false, statusError(err)
	}
	if result.Status == RevocationUnknown && now.Sub(result.ProducedAt) > MaxSuppliedSignerStatusAge {
		then, err := VerifyResponse(response, v.Signer, v.Anchor, NewResponseCheck(result.ProducedAt))
		if err != nil {
			return false, statusError(err)
		}
		if then.Status == RevocationRevoked {
			if err := v.adoptSignerStatus(then, "supplied"); err != nil {
				return false, err
			}
		}
		detail := fmt.Sprintf("the supplied status was produced at %s, older than a published response may be", result.ProducedAt.UTC().Format(time.RFC3339))
		for _, warning := range v.Warnings {
			if warning.Code == "no_ocsp_check" {
				warning.Rule, warning.Detail = "TSLDET-021", detail
				return false, nil
			}
		}
		v.Warnings = append(v.Warnings, &TSLError{"no_ocsp_check", "TSLDET-021", detail})
		return false, nil
	}
	if err := v.adoptSignerStatus(result, "supplied"); err != nil {
		return false, err
	}
	return true, nil
}

func (v *VerifiedTSL) adoptSignerStatus(result *RevocationResult, source string) error {
	switch {
	case result.Status == RevocationGood:
	case result.Status == RevocationRevoked:
		return &TSLError{"cert_revoked", "TSLSIG-041", fmt.Sprintf("the signer is revoked: %s (%s)", result.Reason, source)}
	case result.Reason == unknownStatusReason:
		return &TSLError{"cert_unknown", "TSLSIG-041", fmt.Sprintf("the responder does not know the signer (%s)", source)}
	default:
		return &TSLError{"ocsp_check_revocation_error", "TSLSIG-042", fmt.Sprintf("%s (%s)", result.Reason, source)}
	}
	v.Warnings = slices.DeleteFunc(v.Warnings, func(warning *TSLError) bool { return warning.Code == "no_ocsp_check" })
	v.SignerStatus = result
	return nil
}

func statusError(err error) error {
	failure, ok := errors.AsType[*OCSPError](err)
	if !ok {
		return &TSLError{"ocsp_check_revocation_error", "TSLSIG-042", err.Error()}
	}
	code, rule := "ocsp_check_revocation_error", "TSLSIG-042"
	switch {
	case failure.Code == "ocsp_response_invalid" && failure.defect == defectCertHashMissing:
		code, rule = "certhash_extension_missing", "TSLSIG-041"
	case failure.Code == "ocsp_response_invalid" && failure.defect == defectCertHashMismatch:
		code, rule = "certhash_mismatch", "TSLSIG-041"
	case failure.Code == "ocsp_responder_untrusted", failure.Code == "ocsp_response_invalid" && failure.defect == defectSignature:
		code, rule = "ocsp_signature_error", "TSLSIG-040"
	case failure.Code == "ocsp_unavailable" && !failure.unreachable:
		code, rule = "ocsp_status_error", "TSLSIG-042"
	}
	return &TSLError{code, rule, failure.Message}
}
