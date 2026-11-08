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

// ErrorCode is a stable identifier for why a certificate failed or drew a warning: match on it
// rather than on a message. The values are those of ti-pki's ErrorCode, and spec/pki-profiles holds the
// two to the same list. The SE_ references name the matching gemLibPki GemPkiException codes.
type ErrorCode string

// The codes.
const (
	// CodeRevoked: the certificate is revoked per OCSP (SE_1016).
	CodeRevoked ErrorCode = "revoked"
	// CodeOCSPResponseInvalid: the OCSP response signature failed verification (SE_1033).
	CodeOCSPResponseInvalid ErrorCode = "ocsp_response_invalid"
	// CodeOCSPResponderUntrusted: the OCSP responder certificate is not trusted (SE_1023).
	CodeOCSPResponderUntrusted ErrorCode = "ocsp_responder_untrusted"
	// CodeOCSPUnavailable: the OCSP responder is unreachable or returned non-success (SE_1029).
	CodeOCSPUnavailable ErrorCode = "ocsp_unavailable"
	// CodeUnrecognizedCriticalExtension: a certificate of the chain carries a critical extension that is
	// not processed, which RFC 5280 §4.2 requires to reject.
	CodeUnrecognizedCriticalExtension ErrorCode = "unrecognized_critical_extension"
	// CodeOCSPResponderNotRFC6960 is a warning: the OCSP responder is not authorized under RFC 6960, but
	// was accepted because the verified list names it as an OCSP service (TUC_PKI_006 step 5).
	CodeOCSPResponderNotRFC6960 ErrorCode = "ocsp_responder_not_rfc6960"
	// CodeFQDNMismatch: the domain name in the end entity's commonName is not the one expected
	// (A_30046 (5) of C_12791).
	CodeFQDNMismatch ErrorCode = "fqdn_mismatch"
	// CodeRoleOIDMissing: a required profession or role OID is not in the admission extension (SE_1036).
	CodeRoleOIDMissing ErrorCode = "role_oid_missing"
	// CodeExpired: the certificate's notAfter is in the past (SE_1018).
	CodeExpired ErrorCode = "expired"
	// CodeNotYetValid: the certificate's notBefore is in the future (SE_1018).
	CodeNotYetValid ErrorCode = "not_yet_valid"
	// CodeChainIncomplete: the chain cannot be built to a trusted root, or an AuthorityKeyIdentifier and
	// SubjectKeyIdentifier do not match (SE_1041).
	CodeChainIncomplete ErrorCode = "chain_incomplete"
	// CodePolicyMismatch: a required CertificatePolicy OID is not asserted.
	CodePolicyMismatch ErrorCode = "policy_mismatch"
	// CodeSignatureInvalid: signature verification failed at some level of the chain.
	CodeSignatureInvalid ErrorCode = "signature_invalid"
	// CodeKeyUsageMismatch: a required KeyUsage or ExtendedKeyUsage is missing.
	CodeKeyUsageMismatch ErrorCode = "key_usage_mismatch"
	// CodeKeyNotAdmissible: the end entity's key is of a kind gemSpec_Krypt never admitted for a TI
	// certificate.
	CodeKeyNotAdmissible ErrorCode = "key_not_admissible"
	// CodeKeyPhasedOut is a warning: the end entity's key is past its gemSpec_Krypt "zulässig bis" date.
	CodeKeyPhasedOut ErrorCode = "key_phased_out"
	// CodeProfileNotDetected: automatic profile selection found no type. Reserved for ti-pki's list:
	// [SelectForCert] reports this as [SelectUnclaimed], not as a finding.
	CodeProfileNotDetected ErrorCode = "profile_not_detected"
	// CodeProfileAmbiguous: automatic profile selection found several profiles and none claims the type.
	// Reserved for ti-pki's list: [SelectForCert] reports this as [SelectAmbiguous], not as a finding.
	CodeProfileAmbiguous ErrorCode = "profile_ambiguous"
	// CodeProfileTypeMismatch: the profile does not accept the detected type.
	CodeProfileTypeMismatch ErrorCode = "profile_type_mismatch"
	// CodeCertTypeCANotAuthorized: the issuing CA's entry in the verified TSL does not list the end
	// entity's type (TUC_PKI_007 step 9a, CERT_TYPE_CA_NOT_AUTHORIZED, 1061).
	CodeCertTypeCANotAuthorized ErrorCode = "cert_type_ca_not_authorized"
	// CodeCARevokedInTSL: the TSL lists the issuing CA as revoked, and the end entity was issued at or
	// after that time (Tab_PKI_271, TUC_PKI_002 step 5).
	CodeCARevokedInTSL ErrorCode = "ca_revoked_in_tsl"
	// CodeCANotInTSL: a CA of the chain is not one the verified TSL names as in use.
	CodeCANotInTSL ErrorCode = "ca_not_in_tsl"
	// CodeIssuedBeforeCARevocation is a warning: the TSL lists the issuing CA as revoked, but the end
	// entity was issued before that, so it is treated as usual (Tab_PKI_271).
	CodeIssuedBeforeCARevocation ErrorCode = "issued_before_ca_revocation"
	// CodeRevokedAfterReferenceTime is a warning: OCSP reports the certificate revoked, but after the
	// reference time, so it was valid then (TUC_PKI_006 variant 8a).
	CodeRevokedAfterReferenceTime ErrorCode = "revoked_after_reference_time"
	// CodeIssuedBeforeCAExpiry is a warning: a CA of the chain has expired, but was valid when it issued
	// the certificate below it, which the Kompromissmodell accepts (gemKPT_PKI_TIP 2.4.2, Tab_PKI_271).
	CodeIssuedBeforeCAExpiry ErrorCode = "issued_before_ca_expiry"
)

// ErrorCodes returns every code, in ti-pki's order.
func ErrorCodes() []ErrorCode {
	return []ErrorCode{
		CodeRevoked, CodeOCSPResponseInvalid, CodeOCSPResponderUntrusted, CodeOCSPUnavailable,
		CodeUnrecognizedCriticalExtension, CodeOCSPResponderNotRFC6960, CodeFQDNMismatch, CodeRoleOIDMissing,
		CodeExpired, CodeNotYetValid, CodeChainIncomplete, CodePolicyMismatch, CodeSignatureInvalid,
		CodeKeyUsageMismatch, CodeKeyNotAdmissible, CodeKeyPhasedOut, CodeProfileNotDetected,
		CodeProfileAmbiguous, CodeProfileTypeMismatch, CodeCertTypeCANotAuthorized, CodeCARevokedInTSL,
		CodeCANotInTSL, CodeIssuedBeforeCARevocation, CodeRevokedAfterReferenceTime, CodeIssuedBeforeCAExpiry,
	}
}
