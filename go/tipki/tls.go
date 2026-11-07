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
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// DefaultOCSPGrace is TUC_PKI_018's default OCSP grace period: how long after a response the reference
// time may lie for a stapled response to count (TLSV-032, Tab_PKI_273).
const DefaultOCSPGrace = 10 * time.Minute

// ServerTypes are the types of Tab_PKI_405 a TLS server of the TI presents (TLSV-030).
var ServerTypes = []CertificateType{CertFdTLSS, CertZdTLSS}

// VerdictCode is a result code of spec/pki-validation the ti profile reaches, by its snake_case name.
type VerdictCode string

// The codes.
const (
	// VerdictValid: the server may be trusted.
	VerdictValid VerdictCode = "valid"
	// VerdictTrustMaterialUnavailable: no TSL within its grace period, so no trust store (TLSV-033).
	VerdictTrustMaterialUnavailable VerdictCode = "trust_material_unavailable"
	// VerdictChainIncomplete: no path to an anchor (TLSV-020).
	VerdictChainIncomplete VerdictCode = "chain_incomplete"
	// VerdictNotYetValid (TLSV-021).
	VerdictNotYetValid VerdictCode = "not_yet_valid"
	// VerdictExpired (TLSV-021).
	VerdictExpired VerdictCode = "expired"
	// VerdictKeyUsageMismatch (TLSV-022).
	VerdictKeyUsageMismatch VerdictCode = "key_usage_mismatch"
	// VerdictSignatureAlgorithmNotAllowed: SHA-1, MD5 or SHA-224 in the path (TLSV-023).
	VerdictSignatureAlgorithmNotAllowed VerdictCode = "signature_algorithm_not_allowed"
	// VerdictSignatureInvalid (TLSV-023).
	VerdictSignatureInvalid VerdictCode = "signature_invalid"
	// VerdictProfileTypeMismatch: not a TLS server type (TLSV-030).
	VerdictProfileTypeMismatch VerdictCode = "profile_type_mismatch"
	// VerdictKeyNotAdmissible (TLSV-030, VALID-002).
	VerdictKeyNotAdmissible VerdictCode = "key_not_admissible"
	// VerdictUnrecognizedCriticalExtension (PATH-004).
	VerdictUnrecognizedCriticalExtension VerdictCode = "unrecognized_critical_extension"
	// VerdictCANotInTSL (VALID-006).
	VerdictCANotInTSL VerdictCode = "ca_not_in_tsl"
	// VerdictCertTypeCANotAuthorized (VALID-007).
	VerdictCertTypeCANotAuthorized VerdictCode = "cert_type_ca_not_authorized"
	// VerdictCARevokedInTSL (VALID-003).
	VerdictCARevokedInTSL VerdictCode = "ca_revoked_in_tsl"
	// VerdictNameMismatch (TLSV-024, TLSV-031).
	VerdictNameMismatch VerdictCode = "name_mismatch"
	// VerdictOCSPRevoked (TLSV-032).
	VerdictOCSPRevoked VerdictCode = "ocsp_revoked"
	// VerdictOCSPUnknown (TLSV-032).
	VerdictOCSPUnknown VerdictCode = "ocsp_unknown"
	// VerdictOCSPUnavailable: no responder answered (TLSV-032).
	VerdictOCSPUnavailable VerdictCode = "ocsp_unavailable"
	// VerdictOCSPResponseInvalid: an answer that does not verify or is not authorized (TLSV-032, OCSP-001).
	VerdictOCSPResponseInvalid VerdictCode = "ocsp_response_invalid"
	// VerdictInvalid: a finding the spec has no code of its own for.
	VerdictInvalid VerdictCode = "invalid"
)

// ProvidedOCSPResponseNotValid is TLSV-032's warning: the stapled response did not hold, and the responder
// was asked.
const ProvidedOCSPResponseNotValid = "provided_ocsp_response_not_valid"

// Verdict is what [ServerCheck.Verify] concluded.
type Verdict struct {
	// Code is [VerdictValid] when the server may be trusted.
	Code VerdictCode
	// Detail says why, in words.
	Detail string
	// Warnings never decide.
	Warnings []string
	// NotAfter is the end entity's: no accepted verdict outlives it (TLSV-050). Zero unless an OCSP
	// status was reached.
	NotAfter time.Time
	// ProducedAt is when the OCSP status the verdict rests on was produced: an accepted verdict lives at
	// most OCSP-005's hour past it (TLSV-051). Zero unless an OCSP status was reached.
	ProducedAt time.Time
	// NextUpdate is that status's nextUpdate, zero if the responder set none (TLSV-050, TLSV-051).
	NextUpdate time.Time
}

// Valid says whether the server may be trusted.
func (v Verdict) Valid() bool { return v.Code == VerdictValid }

func refuse(code VerdictCode, detail string, warnings []string) Verdict {
	return Verdict{Code: code, Detail: detail, Warnings: warnings}
}

// ServerCheck is spec/pki-validation's ti profile over one snapshot of the TI's trust material: the
// certificate checks a TLS client makes before it sends anything (GS-A_4662), independent of the TLS
// library that carries the handshake. It holds no state of its own and may be used concurrently.
type ServerCheck struct {
	// Store is the roots and the verified TSL's CAs; nil while no TSL is within its grace period
	// (TLSV-033), which refuses every server.
	Store *TrustStore
	// OCSPGrace is how long after its producedAt a stapled response counts (Tab_PKI_273: configurable).
	OCSPGrace time.Duration
}

// NewServerCheck is the check over store with the default OCSP grace period.
func NewServerCheck(store *TrustStore) *ServerCheck {
	return &ServerCheck{Store: store, OCSPGrace: DefaultOCSPGrace}
}

// Verify judges the server that presented chain (end entity first) for a connection to host, at now, with
// the OCSP response it stapled, nil if none. responder is asked only when no stapled response holds, and
// only about a server that passed everything else (VALID-004); nil leaves no responder to ask.
func (c *ServerCheck) Verify(ctx context.Context, chain []*x509.Certificate, host string, stapled []byte, now time.Time, responder RevocationChecker) Verdict {
	if c.Store == nil {
		return refuse(VerdictTrustMaterialUnavailable, "no TSL within its grace period (GS-A_5336)", nil)
	}
	if len(chain) == 0 {
		return refuse(VerdictChainIncomplete, "the server sent no certificate", nil)
	}
	leaf := chain[0]
	validator := NewValidator(c.Store)
	if detected, ok := DetectCertificateType(leaf); ok && slices.Contains(ServerTypes, detected) {
		validator.WithTypeBaseline(detected)
	}
	validator.AcceptedTypes = ServerTypes
	// Revocation comes last, from the stapled response or the responder (TLSV-032).
	validator.Revocation = RevocationDisabled
	result, err := validator.Validate(ctx, chain, now, nil)
	if err != nil {
		return refuse(VerdictChainIncomplete, err.Error(), nil)
	}
	if len(result.Chain) < 2 {
		return refusal(result.Errors, VerdictChainIncomplete)
	}
	// The path comes before its links (TLSV-020 before TLSV-023): a partial chain that reaches no
	// anchor is incomplete, however its links are signed.
	if i := slices.IndexFunc(result.Errors, func(f Finding) bool { return f.Code == CodeChainIncomplete }); i >= 0 {
		return refuse(VerdictChainIncomplete, result.Errors[i].Message, nil)
	}
	for _, cert := range result.Chain[:len(result.Chain)-1] {
		if name, weak := WeakSignature(cert); weak {
			return refuse(VerdictSignatureAlgorithmNotAllowed, fmt.Sprintf("%q is signed with %s", cert.Subject.CommonName, name), nil)
		}
	}
	if !result.Valid {
		return refusal(result.Errors, VerdictInvalid)
	}
	if !NamesHost(leaf, host) {
		return refuse(VerdictNameMismatch, fmt.Sprintf("%q does not name %s", leaf.Subject.CommonName, host), nil)
	}
	issuer := result.Chain[1]
	var warnings []string
	if len(stapled) > 0 {
		check := NewResponseCheck(now)
		check.MaxResponseAge, check.Store = c.OCSPGrace, c.Store
		// An answer outside the grace period comes back as unknown with the reason; it is no answer, and the
		// responder is asked as if nothing had been stapled.
		status, err := VerifyResponse(stapled, leaf, issuer, check)
		if err == nil && holds(status, now, c.OCSPGrace) {
			return statusVerdict(status, leaf, warnings)
		}
		warnings = append(warnings, ProvidedOCSPResponseNotValid)
	}
	if responder == nil {
		return refuse(VerdictOCSPUnavailable, "no OCSP responder to ask", warnings)
	}
	status, err := responder.Check(ctx, leaf, issuer, c.Store)
	if err != nil {
		code, detail := CodeOCSPUnavailable, err.Error()
		if ocspError, ok := errors.AsType[*OCSPError](err); ok {
			code, detail = ocspError.Code, ocspError.Message
		}
		return refuse(verdictCodeOf(code), detail, warnings)
	}
	return statusVerdict(status, leaf, warnings)
}

// holds says whether a verified stapled status is an answer at now: good or revoked, or unknown and
// produced within grace.
func holds(status *RevocationResult, now time.Time, grace time.Duration) bool {
	return status.Status != RevocationUnknown || (!status.ProducedAt.After(now) && now.Sub(status.ProducedAt) <= grace)
}

func statusVerdict(status *RevocationResult, leaf *x509.Certificate, warnings []string) Verdict {
	code := VerdictOCSPUnknown
	switch status.Status {
	case RevocationGood:
		code = VerdictValid
	case RevocationRevoked:
		code = VerdictOCSPRevoked
	}
	detail := "OCSP: " + string(status.Status)
	if status.Reason != "" {
		detail += ": " + status.Reason
	}
	return Verdict{
		Code: code, Detail: detail, Warnings: warnings,
		NotAfter: leaf.NotAfter, ProducedAt: status.ProducedAt, NextUpdate: status.NextUpdate,
	}
}

func refusal(errs []Finding, fallback VerdictCode) Verdict {
	if len(errs) == 0 {
		return refuse(fallback, "invalid", nil)
	}
	return refuse(verdictCodeOf(errs[0].Code), errs[0].Message, nil)
}

func verdictCodeOf(code ErrorCode) VerdictCode {
	switch code {
	case CodeChainIncomplete:
		return VerdictChainIncomplete
	case CodeNotYetValid:
		return VerdictNotYetValid
	case CodeExpired:
		return VerdictExpired
	case CodeKeyUsageMismatch:
		return VerdictKeyUsageMismatch
	case CodeSignatureInvalid:
		return VerdictSignatureInvalid
	case CodeProfileTypeMismatch, CodeProfileNotDetected, CodePolicyMismatch:
		return VerdictProfileTypeMismatch
	case CodeKeyNotAdmissible:
		return VerdictKeyNotAdmissible
	case CodeUnrecognizedCriticalExtension:
		return VerdictUnrecognizedCriticalExtension
	case CodeCANotInTSL:
		return VerdictCANotInTSL
	case CodeCertTypeCANotAuthorized:
		return VerdictCertTypeCANotAuthorized
	case CodeCARevokedInTSL:
		return VerdictCARevokedInTSL
	case CodeOCSPUnavailable:
		return VerdictOCSPUnavailable
	case CodeOCSPResponseInvalid, CodeOCSPResponderUntrusted:
		return VerdictOCSPResponseInvalid
	}
	return VerdictInvalid
}

// weakSignatures are TLSV-023's SHA-1, MD5 and SHA-224, with RSA and with ECDSA. crypto/x509 has no name
// for SHA-224, so the certificate's own algorithm identifier is read.
var weakSignatures = map[string]string{
	"1.2.840.113549.1.1.5":  "SHA-1 with RSA",
	"1.2.840.113549.1.1.4":  "MD5 with RSA",
	"1.2.840.113549.1.1.14": "SHA-224 with RSA",
	"1.2.840.10045.4.1":     "ECDSA with SHA-1",
	"1.2.840.10045.4.3.1":   "ECDSA with SHA-224",
}

// WeakSignature names the algorithm cert is signed with when it is one of TLSV-023's SHA-1, MD5 or SHA-224.
func WeakSignature(cert *x509.Certificate) (string, bool) {
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.Raw, &outer); err != nil {
		// Parsed certificates were DER already; an outer structure that does not decode is no
		// certificate to trust.
		return "an algorithm that does not decode", true
	}
	name, weak := weakSignatures[outer.Algorithm.Algorithm.String()]
	return name, weak
}

// NamesHost says whether cert names host (TLSV-024, TLSV-031): in its commonName or a dNSName subject
// alternative name, or, for an IP address, in an iPAddress subject alternative name of the same bytes.
func NamesHost(cert *x509.Certificate, host string) bool {
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return false
		}
		return slices.ContainsFunc(cert.IPAddresses, func(named net.IP) bool {
			addr, ok := netip.AddrFromSlice(named)
			return ok && addr == ip
		})
	}
	return DNSNameMatches(cert.Subject.CommonName, host) ||
		slices.ContainsFunc(cert.DNSNames, func(presented string) bool { return DNSNameMatches(presented, host) })
}

// DNSNameMatches compares a presented name with the reference host case-insensitively in ASCII (TLSV-024):
// a wildcard is "*" as the whole leftmost label and stands for exactly one label, under at least two.
func DNSNameMatches(presented, host string) bool {
	presented = strings.TrimSuffix(presented, ".")
	if presented == "" || !isASCII(presented) || !isASCII(host) {
		return false
	}
	rest, wildcard := strings.CutPrefix(presented, "*.")
	if !wildcard {
		return !strings.Contains(presented, "*") && strings.EqualFold(presented, host)
	}
	if strings.Contains(rest, "*") || !strings.Contains(rest, ".") {
		return false
	}
	first, parent, ok := strings.Cut(host, ".")
	return ok && first != "" && strings.EqualFold(parent, rest)
}

func isASCII(text string) bool {
	for i := range len(text) {
		if text[i] >= 0x80 {
			return false
		}
	}
	return true
}
