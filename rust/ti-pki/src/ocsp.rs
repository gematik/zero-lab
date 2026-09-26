//! OCSP (RFC 6960) as the TI uses it: [`request`] builds the query for a certificate,
//! [`verify_response`] decides what an answer is worth, and [`OcspChecker`] (feature
//! `load`) sends one through a [`Transport`](crate::load::Transport).
//!
//! A response counts only if
//!
//! - one of its single responses carries the CertID of the certificate asked about
//!   (serial, and issuer name and key hashed with the algorithm the responder chose),
//! - it is signed by an authorized responder in the sense of RFC 6960 §4.2.2.2: the
//!   issuing CA itself, or a delegate the CA certified directly with
//!   `id-kp-OCSPSigning` and that is valid now. Responders the TSL lists are not
//!   authorized by that fact, since the TSL is not authenticated (see [`crate::tsl`]),
//! - its certHash extension (gemSpec_PKI; Common PKI) hashes this very certificate, and
//! - it lies within the TUC_PKI_006 time window.
//!
//! Failures come back with the codes the [`revocation`](crate::revocation) table
//! decides on; a response outside the time window is an
//! [`Unknown`](RevocationStatus::Unknown) result.
//!
//! The CertID in requests is hashed with SHA-1, as RFC 5019 prescribes and TI
//! responders expect (the TSP responders reject SHA-256 CertIDs as malformed). SHA-1
//! only identifies the certificate there; integrity rests on the response signature
//! and the SHA-256 certHash. Responses may use SHA-1 or SHA-2 CertIDs.

use core::time::Duration;

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::ID_KP_OCSP_SIGNING;
use const_oid::db::rfc5912::{ID_SHA_1, ID_SHA_256, ID_SHA_384, ID_SHA_512};
use const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC;
use der::asn1::{AnyRef, BitStringRef, Null, OctetString, OctetStringRef};
use der::{
    Decode, DecodeValue, Encode, EncodeValue, Enumerated, FixedTag, Header, Length, Reader,
    Sequence, Tag, TagNumber, Tagged, Writer,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::crl::CrlReason;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::Certificate;
use crate::algorithms::{self, AlgorithmSet};
use crate::error::{ErrorCode, ValidationError};
use crate::revocation::{RevocationResult, RevocationStatus};
use crate::time::Timestamp;

/// The clock skew TUC_PKI_006 grants an OCSP responder (gemSpec_PKI: 37.5 s):
/// `thisUpdate` and `producedAt` may lie this far in the future, `nextUpdate` this far
/// in the past.
pub const DEFAULT_CLOCK_TOLERANCE: Duration = Duration::from_millis(37_500);

/// How old `producedAt` may be. TI responders sign every response on demand, so the
/// gematik reference implementation applies the clock tolerance here too; raise it
/// only when responses are served from a cache.
pub const DEFAULT_MAX_RESPONSE_AGE: Duration = DEFAULT_CLOCK_TOLERANCE;

/// `Content-Type` of an OCSP request.
pub const CONTENT_TYPE_REQUEST: &str = "application/ocsp-request";

/// `Content-Type` of an OCSP response.
pub const CONTENT_TYPE_RESPONSE: &str = "application/ocsp-response";

/// id-isismtt-at-certHash (Common PKI Part 4), the single-response extension
/// gemSpec_PKI requires from TI responders: the hash of the whole certificate the
/// status is about, so a response cannot be re-purposed for another certificate with
/// the same serial.
pub const CERT_HASH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.8.3.13");

/// What [`verify_response`] checks against.
#[derive(Clone, Copy, Debug)]
pub struct ResponseCheck<'a> {
    /// The instant the time window is anchored at.
    pub now: Timestamp,
    /// How old `producedAt` may be.
    pub max_response_age: Duration,
    /// The skew allowed between the responder's clock and ours.
    pub clock_tolerance: Duration,
    /// Accept a response without the certHash extension. A certHash that is present is
    /// checked regardless.
    pub allow_missing_cert_hash: bool,
    /// The algorithms the response signature and a delegate's certificate may use.
    pub algorithms: &'a AlgorithmSet,
}

impl<'a> ResponseCheck<'a> {
    /// The strict check at `now`: the default window, certHash required.
    pub fn new(now: Timestamp, algorithms: &'a AlgorithmSet) -> Self {
        ResponseCheck {
            now,
            max_response_age: DEFAULT_MAX_RESPONSE_AGE,
            clock_tolerance: DEFAULT_CLOCK_TOLERANCE,
            allow_missing_cert_hash: false,
            algorithms,
        }
    }
}

/// The DER `OCSPRequest` for `cert`, issued by `issuer`: one request with a SHA-1
/// CertID, unsigned and without nonce (TI responders sign on demand, so a response
/// cannot be older than the time window allows).
///
/// # Panics
///
/// Never: a parsed certificate's serial number and the digests always encode.
pub fn request(cert: &Certificate, issuer: &Certificate) -> Vec<u8> {
    let request = OcspRequest {
        tbs_request: TbsRequest {
            request_list: vec![Request {
                req_cert: CertId {
                    hash_algorithm: AlgorithmIdentifierOwned {
                        oid: ID_SHA_1,
                        parameters: Some(Null.into()),
                    },
                    issuer_name_hash: octets(Sha1::digest(issuer.subject_der()).to_vec()),
                    issuer_key_hash: octets(Sha1::digest(issuer.public_key()).to_vec()),
                    serial_number: SerialNumber::new(cert.serial())
                        .expect("a parsed certificate's serial re-encodes"),
                },
            }],
        },
    };
    request.to_der().expect("an OCSP request encodes")
}

fn octets(bytes: Vec<u8>) -> OctetString {
    OctetString::new(bytes).expect("a digest fits an OCTET STRING")
}

/// Decides what the DER OCSP response `der` says about `cert`, issued by `issuer`.
/// The result's `responder_url` is left empty for the caller to fill in.
///
/// # Errors
///
/// [`ErrorCode::OcspUnavailable`] if the bytes are not an OCSP response or the
/// responder did not answer successfully (`tryLater`, say);
/// [`ErrorCode::OcspResponseInvalid`] if no single response is about `cert`, the
/// signature or the certHash does not verify; [`ErrorCode::OcspResponderUntrusted`] if
/// the signer is not an authorized responder for `issuer`. The subject is `cert`'s
/// common name.
pub fn verify_response(
    der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    check: &ResponseCheck<'_>,
) -> Result<RevocationResult, ValidationError> {
    verify(der, cert, issuer, check).map_err(|e| e.with_subject(cert.subject_cn()))
}

fn verify(
    der: &[u8],
    cert: &Certificate,
    issuer: &Certificate,
    check: &ResponseCheck<'_>,
) -> Result<RevocationResult, ValidationError> {
    let undecodable = |e: der::Error| {
        ValidationError::new(
            ErrorCode::OcspUnavailable,
            "OCSP response could not be decoded",
        )
        .with_cause(e)
    };
    let response = OcspResponse::from_der(der).map_err(undecodable)?;
    if response.response_status != ResponseStatus::Successful {
        return Err(ValidationError::new(
            ErrorCode::OcspUnavailable,
            format!("OCSP responder answered {:?}", response.response_status),
        ));
    }
    let Some(bytes) = response.response_bytes else {
        return Err(ValidationError::new(
            ErrorCode::OcspUnavailable,
            "OCSP response is successful but carries no response",
        ));
    };
    if bytes.response_type != ID_PKIX_OCSP_BASIC {
        return Err(ValidationError::new(
            ErrorCode::OcspUnavailable,
            format!(
                "OCSP response type {} is not id-pkix-ocsp-basic",
                bytes.response_type
            ),
        ));
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).map_err(undecodable)?;
    let tbs_der = basic.tbs_response_data.to_der().map_err(undecodable)?;
    let data = ResponseData::from_der(&tbs_der).map_err(undecodable)?;

    let single = data
        .responses
        .iter()
        .find(|single| cert_id_matches(&single.cert_id, cert, issuer).is_ok())
        .ok_or_else(|| {
            let reason = data.responses.first().map_or_else(
                || "the response holds no single response".to_owned(),
                |first| cert_id_matches(&first.cert_id, cert, issuer).unwrap_err(),
            );
            invalid(format!(
                "OCSP response does not answer for this certificate: {reason}"
            ))
        })?;

    let embedded = basic
        .certs
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|any| {
            let der = any.to_der().map_err(undecodable)?;
            Certificate::from_der(&der).map_err(|e| {
                ValidationError::new(
                    ErrorCode::OcspUnavailable,
                    "OCSP response embeds an unparsable certificate",
                )
                .with_cause(e)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let responder = pick_responder(&data.responder_id, &embedded);
    if let Some(responder) = responder {
        authorize(responder, issuer, check)
            .map_err(|message| ValidationError::new(ErrorCode::OcspResponderUntrusted, message))?;
    }
    let signer = responder.unwrap_or(issuer);
    verify_signature(signer, &basic, &tbs_der, check.algorithms).map_err(|reason| {
        invalid(format!(
            "OCSP response signature does not verify under {:?}: {reason}",
            signer.subject_cn()
        ))
    })?;
    verify_cert_hash(
        single.single_extensions.as_ref(),
        cert,
        check.allow_missing_cert_hash,
    )
    .map_err(invalid)?;

    let mut result = RevocationResult::unknown(check.now, "");
    result.produced_at = Some(data.produced_at.0);
    result.this_update = Some(single.this_update.0);
    result.next_update = single.next_update.map(|t| t.0);
    result.responder = responder.cloned();
    signer.subject_cn().clone_into(&mut result.responder_name);
    der.clone_into(&mut result.raw_response);
    Ok(with_status(result, &single.cert_status, check))
}

/// Fills in what the response says, unless it lies outside the time window, which
/// makes it [`Unknown`](RevocationStatus::Unknown).
fn with_status(
    mut result: RevocationResult,
    status: &CertStatus,
    check: &ResponseCheck<'_>,
) -> RevocationResult {
    if let Some(reason) = outside_window(&result, check) {
        result.reason = reason;
        return result;
    }
    match status {
        CertStatus::Good(_) => result.status = RevocationStatus::Good,
        CertStatus::Revoked(info) => {
            result.status = RevocationStatus::Revoked;
            result.revoked_at = Some(info.revocation_time.0);
            info.revocation_reason
                .map_or("unspecified", reason_name)
                .clone_into(&mut result.reason);
        }
        CertStatus::Unknown(_) => result.reason = "OCSP status: unknown".into(),
    }
    result
}

fn invalid(message: impl Into<String>) -> ValidationError {
    ValidationError::new(ErrorCode::OcspResponseInvalid, message)
}

fn digest(algorithm: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    Some(match *algorithm {
        ID_SHA_1 => Sha1::digest(data).to_vec(),
        ID_SHA_256 => Sha256::digest(data).to_vec(),
        ID_SHA_384 => Sha384::digest(data).to_vec(),
        ID_SHA_512 => Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// Whether `id` names `cert` under `issuer`. The key hash covers the subjectPublicKey
/// bits without tag, length or unused-bits octet (RFC 6960 §4.1.1).
fn cert_id_matches(id: &CertId, cert: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let algorithm = id.hash_algorithm.oid;
    if id.serial_number.as_bytes() != cert.serial() {
        return Err("serial number differs".into());
    }
    let name_hash = digest(&algorithm, issuer.subject_der())
        .ok_or_else(|| format!("unsupported CertID hash algorithm {algorithm}"))?;
    if name_hash != id.issuer_name_hash.as_bytes() {
        return Err("issuerNameHash does not match the issuer".into());
    }
    let key_hash = digest(&algorithm, issuer.public_key()).unwrap_or_default();
    if key_hash != id.issuer_key_hash.as_bytes() {
        return Err("issuerKeyHash does not match the issuer's key".into());
    }
    Ok(())
}

/// The embedded certificate the responder ID names, by name or by the SHA-1 hash of its
/// key, else the first one; the authorization and signature checks decide either way.
fn pick_responder<'c>(
    responder_id: &AnyRef<'_>,
    embedded: &'c [Certificate],
) -> Option<&'c Certificate> {
    let by_name = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(1),
    };
    let by_key = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(2),
    };
    let value = responder_id.value();
    let named = if responder_id.tag() == by_name {
        embedded.iter().find(|c| c.subject_der() == value)
    } else if responder_id.tag() == by_key {
        let key_hash = <&OctetStringRef>::from_der(value).map(OctetStringRef::as_bytes);
        embedded
            .iter()
            .find(|c| key_hash.is_ok_and(|hash| Sha1::digest(c.public_key()).as_slice() == hash))
    } else {
        None
    };
    named.or_else(|| embedded.first())
}

/// RFC 6960 §4.2.2.2: the issuer itself, or a delegate the issuer signed that carries
/// id-kp-OCSPSigning and is valid now.
fn authorize(
    responder: &Certificate,
    issuer: &Certificate,
    check: &ResponseCheck<'_>,
) -> Result<(), String> {
    if responder.subject_der() == issuer.subject_der()
        && responder.public_key() == issuer.public_key()
    {
        return Ok(());
    }
    let (name, ca) = (responder.subject_cn(), issuer.subject_cn());
    if responder.issuer_der() != issuer.subject_der() {
        return Err(format!(
            "OCSP responder {name:?} was certified by {:?}, but the certificate was issued \
             by {ca:?}; RFC 6960 accepts only the issuing CA or a responder it certified \
             directly (the responder's own chain is not followed to a root)",
            responder.issuer_cn()
        ));
    }
    responder
        .verify_signed_by(issuer, check.algorithms)
        .map_err(|e| {
            format!(
                "OCSP responder {name:?} names the issuing CA {ca:?} as its issuer, but its \
             certificate does not verify under the CA's key: {e}"
            )
        })?;
    if !responder.ext_key_usage().contains(&ID_KP_OCSP_SIGNING) {
        return Err(format!(
            "OCSP responder {name:?}, certified by the issuing CA {ca:?}, lacks \
             id-kp-OCSPSigning"
        ));
    }
    let skew = check.clock_tolerance.as_secs();
    let valid = responder.is_valid_at(Timestamp(check.now.0.saturating_add(skew)))
        || responder.is_valid_at(Timestamp(check.now.0.saturating_sub(skew)));
    if !valid {
        return Err(format!(
            "OCSP responder {name:?}, certified by the issuing CA {ca:?}, is not valid at {} \
             (valid {} to {})",
            check.now,
            responder.not_before(),
            responder.not_after()
        ));
    }
    Ok(())
}

fn verify_signature(
    signer: &Certificate,
    basic: &BasicOcspResponse<'_>,
    tbs_der: &[u8],
    set: &AlgorithmSet,
) -> Result<(), String> {
    let algorithm = algorithms::find(
        set,
        &signer.public_key_alg_id(),
        basic.signature_algorithm.value(),
    )
    .ok_or("no configured algorithm handles the signer's key and signature algorithm")?;
    algorithm
        .verify_signature(signer.public_key(), tbs_der, basic.signature.raw_bytes())
        .map_err(|_| "invalid signature".to_owned())
}

fn verify_cert_hash(
    extensions: Option<&Extensions>,
    cert: &Certificate,
    allow_missing: bool,
) -> Result<(), String> {
    let Some(extension) = extensions
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == CERT_HASH)
    else {
        return if allow_missing {
            Ok(())
        } else {
            Err("OCSP response carries no certHash extension".into())
        };
    };
    let cert_hash = CertHash::from_der(extension.extn_value.as_bytes())
        .map_err(|e| format!("OCSP certHash extension is malformed: {e}"))?;
    let algorithm = cert_hash.hash_algorithm.oid;
    let expected = digest(&algorithm, cert.der())
        .ok_or_else(|| format!("OCSP certHash uses unsupported hash algorithm {algorithm}"))?;
    if expected != cert_hash.certificate_hash.as_bytes() {
        return Err("OCSP certHash does not match the certificate".into());
    }
    Ok(())
}

/// The TUC_PKI_006 window: `producedAt` within `[now - max age, now + tolerance]`,
/// `thisUpdate` at most the tolerance in the future, `nextUpdate` (if set) at most the
/// tolerance in the past. `None` inside it.
fn outside_window(result: &RevocationResult, check: &ResponseCheck<'_>) -> Option<String> {
    let millis = |t: Timestamp| i128::from(t.0) * 1000;
    let now = millis(check.now);
    let max_age = i128::try_from(check.max_response_age.as_millis()).unwrap_or(i128::MAX);
    let skew = i128::try_from(check.clock_tolerance.as_millis()).unwrap_or(i128::MAX);
    let seconds = |ms: i128| ms / 1000;
    let produced = millis(result.produced_at?);
    if now - produced > max_age {
        return Some(format!(
            "OCSP response is {} s old, more than the {} s allowed",
            seconds(now - produced),
            seconds(max_age)
        ));
    }
    if produced - now > skew {
        return Some(format!(
            "OCSP producedAt lies {} s in the future",
            seconds(produced - now)
        ));
    }
    let this_update = millis(result.this_update?);
    if this_update - now > skew {
        return Some(format!(
            "OCSP thisUpdate lies {} s in the future",
            seconds(this_update - now)
        ));
    }
    if let Some(next_update) = result.next_update.map(millis)
        && now - next_update > skew
    {
        return Some(format!(
            "OCSP nextUpdate passed {} s ago",
            seconds(now - next_update)
        ));
    }
    None
}

fn reason_name(reason: CrlReason) -> &'static str {
    match reason {
        CrlReason::Unspecified => "unspecified",
        CrlReason::KeyCompromise => "keyCompromise",
        CrlReason::CaCompromise => "cACompromise",
        CrlReason::AffiliationChanged => "affiliationChanged",
        CrlReason::Superseded => "superseded",
        CrlReason::CessationOfOperation => "cessationOfOperation",
        CrlReason::CertificateHold => "certificateHold",
        CrlReason::RemoveFromCRL => "removeFromCRL",
        CrlReason::PrivilegeWithdrawn => "privilegeWithdrawn",
        CrlReason::AaCompromise => "aACompromise",
    }
}

#[cfg(feature = "load")]
pub use checker::OcspChecker;

#[cfg(feature = "load")]
mod checker {
    use std::borrow::Cow;

    use super::{
        CONTENT_TYPE_REQUEST, CONTENT_TYPE_RESPONSE, DEFAULT_MAX_RESPONSE_AGE, ResponseCheck,
        request, verify_response,
    };
    use crate::algorithms::AlgorithmSet;
    use crate::error::{ErrorCode, ValidationError};
    use crate::load::{PostRequest, Transport};
    use crate::revocation::{RevocationChecker, RevocationResult};
    use crate::time::Clock;
    use crate::{Certificate, TrustConfig};

    /// Queries a certificate's OCSP responder through a [`Transport`] and verifies the
    /// answer with [`verify_response`](super::verify_response). The transport owns
    /// timeouts, proxies and retries.
    #[derive(Clone, Debug)]
    pub struct OcspChecker<T, C> {
        transport: T,
        clock: C,
        algorithms: Cow<'static, AlgorithmSet>,
        clock_tolerance: core::time::Duration,
        max_response_age: core::time::Duration,
        allow_missing_cert_hash: bool,
        responder_url: Option<String>,
    }

    impl<T: Transport, C: Clock> OcspChecker<T, C> {
        /// A strict checker with `config`'s algorithms and clock skew, asking the
        /// responder named in each certificate's authority information access.
        pub fn new(config: &TrustConfig, transport: T, clock: C) -> Self {
            OcspChecker {
                transport,
                clock,
                algorithms: config.algorithms.clone(),
                clock_tolerance: config.max_clock_skew,
                max_response_age: DEFAULT_MAX_RESPONSE_AGE,
                allow_missing_cert_hash: false,
                responder_url: None,
            }
        }

        /// Sends every request to `url` instead of the certificate's own responder,
        /// e.g. a relay where the TI responders are not reachable directly.
        #[must_use]
        pub fn with_responder_url(mut self, url: impl Into<String>) -> Self {
            self.responder_url = Some(url.into());
            self
        }

        /// Accepts responses up to `age` old, for responses served from a cache.
        #[must_use]
        pub fn with_max_response_age(mut self, age: core::time::Duration) -> Self {
            self.max_response_age = age;
            self
        }

        /// Accepts responses without the certHash extension, for responders outside
        /// the TI.
        #[must_use]
        pub fn allowing_missing_cert_hash(mut self) -> Self {
            self.allow_missing_cert_hash = true;
            self
        }
    }

    impl<T: Transport, C: Clock> RevocationChecker for OcspChecker<T, C> {
        /// No responder URL is an [`Unknown`](crate::revocation::RevocationStatus::Unknown)
        /// result: no other source could answer for such a certificate either. A
        /// transport failure is [`ErrorCode::OcspUnavailable`].
        async fn check(
            &self,
            cert: &Certificate,
            issuer: &Certificate,
        ) -> Result<RevocationResult, ValidationError> {
            let Some(url) = self
                .responder_url
                .as_deref()
                .or_else(|| cert.ocsp_urls().first().map(String::as_str))
            else {
                return Ok(RevocationResult::unknown(
                    self.clock.now(),
                    "no OCSP responder URL (no authority information access, no override)",
                ));
            };
            let body = request(cert, issuer);
            let response = self
                .transport
                .post(&PostRequest {
                    url,
                    content_type: CONTENT_TYPE_REQUEST,
                    accept: CONTENT_TYPE_RESPONSE,
                    body: &body,
                })
                .await
                .map_err(|e| {
                    ValidationError::new(
                        ErrorCode::OcspUnavailable,
                        format!("OCSP responder {url} unreachable"),
                    )
                    .with_subject(cert.subject_cn())
                    .with_cause(e)
                })?;
            let check = ResponseCheck {
                now: self.clock.now(),
                max_response_age: self.max_response_age,
                clock_tolerance: self.clock_tolerance,
                allow_missing_cert_hash: self.allow_missing_cert_hash,
                algorithms: &self.algorithms,
            };
            let mut result = verify_response(&response, cert, issuer, &check)?;
            url.clone_into(&mut result.responder_url);
            Ok(result)
        }
    }
}

// RFC 6960 ASN.1, the subset the TI uses. Raw slices (`AnyRef`) keep the bytes the
// signature covers exactly as received.

#[derive(Sequence)]
struct OcspRequest {
    tbs_request: TbsRequest,
}

#[derive(Sequence)]
struct TbsRequest {
    request_list: Vec<Request>,
}

#[derive(Sequence)]
struct Request {
    req_cert: CertId,
}

#[derive(Clone, Debug, Sequence)]
struct CertId {
    hash_algorithm: AlgorithmIdentifierOwned,
    issuer_name_hash: OctetString,
    issuer_key_hash: OctetString,
    serial_number: SerialNumber,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumerated)]
#[repr(u8)]
enum ResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

#[derive(Sequence)]
struct OcspResponse<'a> {
    response_status: ResponseStatus,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    response_bytes: Option<ResponseBytes<'a>>,
}

#[derive(Sequence)]
struct ResponseBytes<'a> {
    response_type: ObjectIdentifier,
    response: &'a OctetStringRef,
}

#[derive(Sequence)]
struct BasicOcspResponse<'a> {
    tbs_response_data: AnyRef<'a>,
    signature_algorithm: AnyRef<'a>,
    signature: BitStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    certs: Option<Vec<AnyRef<'a>>>,
}

#[derive(Sequence)]
#[allow(dead_code, reason = "decoded to match the ASN.1 structure, not read")]
struct ResponseData<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    version: Option<u8>,
    responder_id: AnyRef<'a>,
    produced_at: Time,
    responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    response_extensions: Option<Extensions>,
}

#[derive(Sequence)]
struct SingleResponse {
    cert_id: CertId,
    cert_status: CertStatus,
    this_update: Time,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    next_update: Option<Time>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    single_extensions: Option<Extensions>,
}

use cert_status::CertStatus;

mod cert_status {
    #![allow(
        clippy::unnested_or_patterns,
        reason = "in the code the Choice derive generates"
    )]

    use der::Choice;
    use der::asn1::Null;

    use super::RevokedInfo;

    #[derive(Choice)]
    pub(super) enum CertStatus {
        #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
        Good(Null),
        #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
        Revoked(RevokedInfo),
        #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
        Unknown(Null),
    }
}

#[derive(Sequence)]
struct RevokedInfo {
    revocation_time: Time,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    revocation_reason: Option<CrlReason>,
}

#[derive(Sequence)]
struct CertHash {
    hash_algorithm: AlgorithmIdentifierOwned,
    certificate_hash: OctetString,
}

/// A GeneralizedTime that, unlike RFC 5280's, may carry fractions of a second, as
/// RFC 6960 allows; they are dropped.
#[derive(Clone, Copy, Debug)]
struct Time(Timestamp);

impl FixedTag for Time {
    const TAG: Tag = Tag::GeneralizedTime;
}

impl<'a> DecodeValue<'a> for Time {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        let bytes = reader.read_slice(header.length())?;
        parse_generalized_time(bytes)
            .map(Time)
            .ok_or_else(|| reader.error(Tag::GeneralizedTime.value_error()))
    }
}

impl EncodeValue for Time {
    fn value_len(&self) -> der::Result<Length> {
        Length::try_from(15_usize)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        let rfc3339 = self.0.to_string();
        let digits: String = rfc3339.chars().filter(char::is_ascii_digit).collect();
        writer.write(digits.as_bytes())?;
        writer.write(b"Z")
    }
}

/// `YYYYMMDDHHMMSS[.f+]Z`.
fn parse_generalized_time(bytes: &[u8]) -> Option<Timestamp> {
    let s = core::str::from_utf8(bytes).ok()?;
    if s.len() < 15 || !s[..14].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let rest = &s[14..];
    let fraction_ok = rest == "Z"
        || rest
            .strip_prefix('.')
            .and_then(|f| f.strip_suffix('Z'))
            .is_some_and(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()));
    if !fraction_ok {
        return None;
    }
    Timestamp::parse_rfc3339(&format!(
        "{}-{}-{}T{}:{}:{}Z",
        &s[0..4],
        &s[4..6],
        &s[6..8],
        &s[8..10],
        &s[10..12],
        &s[12..14]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::{RCA5, SMCB_CA51, fixture};

    macro_rules! response {
        ($name:literal) => {
            include_bytes!(concat!("../tests/pki/ocsp/", $name, ".der")).as_slice()
        };
    }

    fn at(rfc3339: &str) -> Timestamp {
        Timestamp::parse_rfc3339(rfc3339).unwrap()
    }

    #[test]
    fn generalized_time_with_and_without_fractions() {
        let t = at("2026-09-23T18:44:38Z");
        assert_eq!(parse_generalized_time(b"20260923184438Z"), Some(t));
        assert_eq!(parse_generalized_time(b"20260923184438.123Z"), Some(t));
        for bad in [
            &b"20260923184438"[..],
            b"20260923184438.Z",
            b"2026092318443Z",
            b"20260923184438+0100",
        ] {
            assert_eq!(parse_generalized_time(bad), None, "{bad:?}");
        }
    }

    /// A live answer of the reference environment's root responder for GEM.SMCB-CA51
    /// TEST-ONLY: a delegate of GEM.RCA5 TEST-ONLY with certHash, no nextUpdate.
    #[test]
    fn real_root_responder_answer() {
        let (ca, root) = (fixture(SMCB_CA51), fixture(RCA5));
        let der = include_bytes!("../tests/fixtures/ocsp-smcb-ca51-test-only.der");
        let produced = at("2026-09-23T18:44:38Z");
        let result = verify_response(
            der,
            &ca,
            &root,
            &ResponseCheck::new(produced, algorithms::DEFAULT),
        )
        .unwrap();
        assert_eq!(result.status, RevocationStatus::Good);
        assert_eq!(result.responder_name, "Root-CA5 OCSP-Signer1 TEST-ONLY");
        assert_eq!(result.produced_at, Some(produced));
        assert_eq!(result.next_update, None);

        let late = ResponseCheck::new(Timestamp(produced.0 + 60), algorithms::DEFAULT);
        let stale = verify_response(der, &ca, &root, &late).unwrap();
        assert_eq!(stale.status, RevocationStatus::Unknown);
        assert_eq!(
            stale.reason,
            "OCSP response is 60 s old, more than the 37 s allowed"
        );

        // The same question with the SHA-1 CertID the request builder sends.
        let sha1 = include_bytes!("../tests/fixtures/ocsp-smcb-ca51-test-only-sha1.der");
        let now = ResponseCheck::new(produced, algorithms::DEFAULT);
        let result = verify_response(sha1, &ca, &root, &now).unwrap();
        assert_eq!(result.status, RevocationStatus::Good);
    }

    #[test]
    fn request_carries_a_sha1_cert_id() {
        let (ca, root) = (fixture(SMCB_CA51), fixture(RCA5));
        let der = request(&ca, &root);
        let request = OcspRequest::from_der(&der).unwrap();
        let id = &request.tbs_request.request_list[0].req_cert;
        assert_eq!(id.hash_algorithm.oid, ID_SHA_1);
        cert_id_matches(id, &ca, &root).unwrap();
        assert_eq!(
            cert_id_matches(id, &fixture(RCA5), &root).unwrap_err(),
            "serial number differs"
        );
    }

    #[cfg(feature = "brainpool")]
    mod openssl {
        use super::*;
        use crate::testing::TestPki;

        fn verify_at(
            der: &[u8],
            cert: &Certificate,
            issuer: &Certificate,
            now: Timestamp,
        ) -> Result<RevocationResult, ValidationError> {
            verify_response(
                der,
                cert,
                issuer,
                &ResponseCheck::new(now, algorithms::DEFAULT),
            )
        }

        fn verify(
            der: &[u8],
            cert: &Certificate,
            issuer: &Certificate,
        ) -> Result<RevocationResult, ValidationError> {
            verify_at(der, cert, issuer, TestPki::NOW)
        }

        #[test]
        fn good_revoked_unknown() {
            let pki = TestPki::new();
            let good = verify(response!("good"), &pki.ee_arzt, &pki.sub_ca_hba).unwrap();
            assert_eq!(good.status, RevocationStatus::Good);
            assert_eq!(good.responder_name, "SubCA-HBA OCSP-Signer TEST-ONLY");
            assert_eq!(good.next_update, Some(at("2026-01-02T00:00:00Z")));
            assert!(good.responder.is_some());

            let revoked = verify(response!("revoked"), &pki.ee_revoked, &pki.sub_ca_hba).unwrap();
            assert_eq!(revoked.status, RevocationStatus::Revoked);
            assert_eq!(revoked.revoked_at, Some(at("2025-12-01T00:00:00Z")));
            assert_eq!(revoked.reason, "keyCompromise");

            let unknown = verify(response!("unknown"), &pki.ee_arzt, &pki.sub_ca_hba).unwrap();
            assert_eq!(unknown.status, RevocationStatus::Unknown);
            assert_eq!(unknown.reason, "OCSP status: unknown");
        }

        #[test]
        fn issuer_signed_answer_for_a_sub_ca() {
            let pki = TestPki::new();
            let result = verify(response!("issuer-signed"), &pki.sub_ca_hba, &pki.rca1).unwrap();
            assert_eq!(result.status, RevocationStatus::Good);
            assert_eq!(result.responder_name, "GEM.RCA1 TEST-ONLY");
            assert!(result.responder.is_none());
        }

        #[test]
        fn unauthorized_responders() {
            let pki = TestPki::new();
            for (der, message) in [
                (
                    response!("no-eku"),
                    "OCSP responder \"SubCA-HBA No-EKU-Signer TEST-ONLY\", certified by the \
                     issuing CA \"GEM.SubCA-HBA TEST-ONLY\", lacks id-kp-OCSPSigning",
                ),
                (
                    response!("foreign-responder"),
                    "OCSP responder \"SubCA-Komp OCSP-Signer TEST-ONLY\" was certified by \
                     \"GEM.SubCA-Komp TEST-ONLY\", but the certificate was issued by \
                     \"GEM.SubCA-HBA TEST-ONLY\"; RFC 6960 accepts only the issuing CA or a \
                     responder it certified directly (the responder's own chain is not \
                     followed to a root)",
                ),
                (
                    response!("expired-responder"),
                    "OCSP responder \"SubCA-HBA Expired-Signer TEST-ONLY\", certified by the \
                     issuing CA \"GEM.SubCA-HBA TEST-ONLY\", is not valid at \
                     2026-01-01T00:00:00Z (valid 2024-01-01T00:00:00Z to 2025-12-31T00:00:00Z)",
                ),
            ] {
                let error = verify(der, &pki.ee_arzt, &pki.sub_ca_hba).unwrap_err();
                assert_eq!(error.code, ErrorCode::OcspResponderUntrusted, "{error}");
                assert_eq!(error.message, message);
                assert_eq!(error.subject, "Dr. Arzt TEST-ONLY");
            }
        }

        #[test]
        fn response_for_another_certificate() {
            let pki = TestPki::new();
            let error = verify(response!("good"), &pki.ee_revoked, &pki.sub_ca_hba).unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspResponseInvalid);
            assert_eq!(
                error.message,
                "OCSP response does not answer for this certificate: serial number differs"
            );
            let error = verify(response!("good"), &pki.ee_arzt, &pki.sub_ca_komp).unwrap_err();
            assert!(
                error
                    .message
                    .ends_with("issuerNameHash does not match the issuer"),
                "{error}"
            );
        }

        #[test]
        fn tampered_signature() {
            let pki = TestPki::new();
            let mut der = response!("issuer-signed").to_vec();
            // The last byte is the end of the ECDSA signature's s value.
            *der.last_mut().unwrap() ^= 1;
            let error = verify(&der, &pki.sub_ca_hba, &pki.rca1).unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspResponseInvalid);
            assert_eq!(
                error.message,
                "OCSP response signature does not verify under \"GEM.RCA1 TEST-ONLY\": \
                 invalid signature"
            );
        }

        #[test]
        fn cert_hash() {
            let pki = TestPki::new();
            let error =
                verify(response!("no-cert-hash"), &pki.ee_arzt, &pki.sub_ca_hba).unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspResponseInvalid);
            assert_eq!(error.message, "OCSP response carries no certHash extension");
            let relaxed = ResponseCheck {
                allow_missing_cert_hash: true,
                ..ResponseCheck::new(TestPki::NOW, algorithms::DEFAULT)
            };
            let result = verify_response(
                response!("no-cert-hash"),
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &relaxed,
            )
            .unwrap();
            assert_eq!(result.status, RevocationStatus::Good);

            let error = verify_response(
                response!("wrong-cert-hash"),
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &relaxed,
            )
            .unwrap_err();
            assert_eq!(
                error.message,
                "OCSP certHash does not match the certificate"
            );
        }

        #[test]
        fn time_window() {
            let pki = TestPki::new();
            let (ee, ca) = (&pki.ee_arzt, &pki.sub_ca_hba);
            let window = |now: Timestamp| {
                let result = verify_at(response!("good"), ee, ca, now).unwrap();
                (result.status == RevocationStatus::Good)
                    .then_some(())
                    .ok_or(result.reason)
            };
            let now = TestPki::NOW.0;
            window(Timestamp(now + 37)).unwrap();
            window(Timestamp(now - 37)).unwrap();
            assert_eq!(
                window(Timestamp(now + 38)).unwrap_err(),
                "OCSP response is 38 s old, more than the 37 s allowed"
            );
            // Ahead of NOW the delegate's own certificate is not valid yet; an answer the
            // CA signed itself shows the window alone.
            let early = verify_at(
                response!("issuer-signed"),
                &pki.sub_ca_hba,
                &pki.rca1,
                Timestamp(now - 38),
            )
            .unwrap();
            assert_eq!(early.reason, "OCSP producedAt lies 38 s in the future");

            let cached = ResponseCheck {
                max_response_age: Duration::from_hours(72),
                ..ResponseCheck::new(Timestamp(now + 86_400 + 38), algorithms::DEFAULT)
            };
            let result = verify_response(response!("good"), ee, ca, &cached).unwrap();
            assert_eq!(result.reason, "OCSP nextUpdate passed 38 s ago");
        }

        #[test]
        fn undecodable_and_unsuccessful() {
            let pki = TestPki::new();
            let (ee, ca) = (&pki.ee_arzt, &pki.sub_ca_hba);
            for (der, message) in [
                (&b"<html>"[..], "OCSP response could not be decoded"),
                (
                    &[0x30, 0x03, 0x0a, 0x01, 0x03],
                    "OCSP responder answered TryLater",
                ),
                (
                    &[0x30, 0x03, 0x0a, 0x01, 0x00],
                    "OCSP response is successful but carries no response",
                ),
            ] {
                let error = verify(der, ee, ca).unwrap_err();
                assert_eq!(error.code, ErrorCode::OcspUnavailable);
                assert_eq!(error.message, message);
            }
        }

        #[cfg(feature = "load")]
        #[test]
        fn checker_posts_and_verifies() {
            use crate::load::{MockTransport, TransportError, TransportErrorKind};
            use crate::revocation::RevocationChecker;
            use crate::time::FixedClock;

            let pki = TestPki::new();
            let config = crate::TrustConfig::for_anchor(pki.rca1.der().to_vec());
            let transport = MockTransport::posting([
                Ok(response!("good").to_vec()),
                Err(TransportError {
                    kind: TransportErrorKind::Network,
                    message: "connection refused".into(),
                    retryable: true,
                }),
            ]);
            let checker = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW))
                .with_responder_url("http://ocsp.test/");
            let result =
                futures_lite::future::block_on(checker.check(&pki.ee_arzt, &pki.sub_ca_hba))
                    .unwrap();
            assert_eq!(result.status, RevocationStatus::Good);
            assert_eq!(result.responder_url, "http://ocsp.test/");
            let posts = transport.posts();
            assert_eq!(posts[0].0, "http://ocsp.test/");
            assert_eq!(posts[0].1, request(&pki.ee_arzt, &pki.sub_ca_hba));

            let error =
                futures_lite::future::block_on(checker.check(&pki.ee_arzt, &pki.sub_ca_hba))
                    .unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspUnavailable);
            assert_eq!(
                error.to_string(),
                "ti-pki[ocsp_unavailable]: OCSP responder http://ocsp.test/ unreachable: \
                 \"Dr. Arzt TEST-ONLY\": network error: connection refused"
            );

            let without_url = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW));
            let result =
                futures_lite::future::block_on(without_url.check(&pki.ee_arzt, &pki.sub_ca_hba))
                    .unwrap();
            assert_eq!(result.status, RevocationStatus::Unknown);
            assert!(result.reason.starts_with("no OCSP responder URL"));
        }
    }
}
