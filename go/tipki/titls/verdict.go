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

package titls

import (
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// Code is a result code of spec/pki-validation, by its snake_case name. The ti profile's codes are tipki's,
// spelled the same.
type Code string

// The codes.
const (
	// Valid: the server may be trusted.
	Valid Code = "valid"
	// TrustMaterialUnavailable (TLSV-033).
	TrustMaterialUnavailable Code = "trust_material_unavailable"
	// ChainIncomplete (TLSV-020).
	ChainIncomplete Code = "chain_incomplete"
	// NotYetValid (TLSV-021).
	NotYetValid Code = "not_yet_valid"
	// Expired (TLSV-021).
	Expired Code = "expired"
	// KeyUsageMismatch (TLSV-022).
	KeyUsageMismatch Code = "key_usage_mismatch"
	// SignatureAlgorithmNotAllowed (TLSV-023).
	SignatureAlgorithmNotAllowed Code = "signature_algorithm_not_allowed"
	// SignatureInvalid (TLSV-023).
	SignatureInvalid Code = "signature_invalid"
	// NameMismatch (TLSV-024, TLSV-031, TLSV-043).
	NameMismatch Code = "name_mismatch"
	// ProfileTypeMismatch (TLSV-030).
	ProfileTypeMismatch Code = "profile_type_mismatch"
	// KeyNotAdmissible (TLSV-030, TLSV-041, TLSV-042).
	KeyNotAdmissible Code = "key_not_admissible"
	// UnrecognizedCriticalExtension (PATH-004).
	UnrecognizedCriticalExtension Code = "unrecognized_critical_extension"
	// CANotInTSL (VALID-006).
	CANotInTSL Code = "ca_not_in_tsl"
	// CertTypeCANotAuthorized (VALID-007).
	CertTypeCANotAuthorized Code = "cert_type_ca_not_authorized"
	// CARevokedInTSL (VALID-003).
	CARevokedInTSL Code = "ca_revoked_in_tsl"
	// OCSPRevoked (TLSV-032).
	OCSPRevoked Code = "ocsp_revoked"
	// OCSPUnknown (TLSV-032).
	OCSPUnknown Code = "ocsp_unknown"
	// OCSPUnavailable (TLSV-032).
	OCSPUnavailable Code = "ocsp_unavailable"
	// OCSPResponseInvalid (TLSV-032).
	OCSPResponseInvalid Code = "ocsp_response_invalid"
	// Revoked (TLSV-044).
	Revoked Code = "revoked"
	// RevocationUnavailable (TLSV-044) before its deviation; the web profile now accepts such a server with
	// [WarningRevocationUnavailable] and returns this code no more.
	RevocationUnavailable Code = "revocation_unavailable"
	// ValidityTooLong (TLSV-045).
	ValidityTooLong Code = "validity_too_long"
	// Invalid: a finding the spec has no code of its own for.
	Invalid Code = "invalid"
)

// The warnings of the web profile's deviations (spec/pki-validation, Deviations).
const (
	// WarningKeyPhasedOut (TLSV-041): an end-entity RSA key of 2048 to 2999 bits, accepted though below
	// A_28976's 3000; tipki gives the same key the same code.
	WarningKeyPhasedOut = "key_phased_out"
	// WarningRevocationUnavailable (TLSV-044): no source gave the end entity's revocation status, and the
	// server was accepted without one (A_27857-02).
	WarningRevocationUnavailable = "revocation_unavailable"
)

// Verdict is what a check concluded about a server.
type Verdict struct {
	// Code is [Valid] when the server may be trusted.
	Code Code
	// Detail says why, in words.
	Detail string
	// Warnings never decide.
	Warnings []string
	// ReusableUntil is the instant from which an accepted verdict may no longer be reused (TLSV-050,
	// TLSV-051); zero for a refusal, which is never reused, and for a verdict that rests on no revocation
	// status.
	ReusableUntil time.Time
}

// Valid says whether the server may be trusted.
func (v Verdict) Valid() bool { return v.Code == Valid }

func refuse(code Code, detail string) Verdict {
	return Verdict{Code: code, Detail: detail}
}

// fromTI carries tipki's verdict over; the codes are spelled alike.
func fromTI(verdict tipki.Verdict) Verdict {
	return Verdict{Code: Code(verdict.Code), Detail: verdict.Detail, Warnings: verdict.Warnings}
}

// RefusedError is how a configuration of this package ends a handshake whose server was refused; crypto/tls
// sends the fatal alert (TLSV-002).
type RefusedError struct {
	Verdict Verdict
}

func (e *RefusedError) Error() string {
	return "titls: server refused: " + string(e.Verdict.Code) + ": " + e.Verdict.Detail
}
