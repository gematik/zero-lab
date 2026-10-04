//! OCSP (RFC 6960) as the TI uses it: [`request`] builds the query for a certificate,
//! [`verify_response`] decides what an answer is worth, and [`OcspChecker`] (feature
//! `load`) sends one through a [`Transport`](crate::load::Transport).
//!
//! A response counts only if
//!
//! - one of its single responses carries the CertID of the certificate asked about
//!   (serial, and issuer name and key hashed with the algorithm the responder chose),
//! - it is signed by an authorized responder: in the sense of RFC 6960 §4.2.2.2 the
//!   issuing CA itself, or a delegate the CA certified directly with
//!   `id-kp-OCSPSigning` and that is valid now; otherwise, given a trust store, a
//!   delegate of the same kind certified by another CA of the issuing CA's TSP (see
//!   below),
//! - its certHash extension (gemSpec_PKI; Common PKI) hashes this very certificate, and
//! - it lies within the TUC_PKI_006 time window.
//!
//! # Responders of the same TSP
//!
//! TI TSPs run one responder for several of their CAs: gematik's ehca, for one, signs
//! answers for GEM.SMCB-CA51 with a delegate of GEM.KOMP-CA51. gemSpec_PKI authorizes
//! such responders by their TSL listing; the TSL ties a responder to CAs only by the TSP
//! it lists both under. Such a responder is accepted when its certificate verifies under
//! a TSL CA that a trusted root signed and that CA is listed under the same TSP as the
//! issuing CA, so a listing never lets a responder answer for another TSP's CAs. If the
//! verified TSL also lists the responder as an OCSP service of that TSP
//! ([`TrustStore::listed_responder_tsps`]), it is
//! [`ResponderAuthorization::TslListed`]; otherwise
//! [`ResponderAuthorization::SameTspDelegate`], a deviation the
//! [`Validator`](crate::Validator) reports as an [`ErrorCode::OcspResponderNotRfc6960`]
//! warning.
//!
//! gemSpec_PKI itself only requires the responder certificate to be among the TSL's OCSP
//! services (TUC_PKI_006 step 5); the TSL binds an OCSP service to no CA and no
//! certificate type (its extension is `oid_tsl_placeholder`, gemSpec_TSL TIP1-A_4108).
//! Responders do cross certificate families within a TSP (ehca's GEM.KOMP-CA51 delegate
//! answers for GEM.SMCB-CA51), so the TSP is the narrowest boundary the data supports.
//! New responder certificates must follow RFC 6960 option 2 (A_23142-01).
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

use crate::algorithms::{self, AlgorithmSet};
use crate::error::{ErrorCode, ValidationError};
use crate::revocation::{
    ResponderAuthorization, RevocationChecker, RevocationResult, RevocationStatus,
};
use crate::time::Timestamp;
use crate::{Certificate, TrustStore};

/// The clock skew TUC_PKI_006 grants an OCSP responder (gemSpec_PKI: 37.5 s):
/// `thisUpdate` and `producedAt` may lie this far in the future, `nextUpdate` this far
/// in the past.
pub const DEFAULT_CLOCK_TOLERANCE: Duration = Duration::from_millis(37_500);

/// How old `producedAt` may be. TI responders sign every response on demand, so the
/// gematik reference implementation applies the clock tolerance here too; raise it
/// only when responses are served from a cache.
pub const DEFAULT_MAX_RESPONSE_AGE: Duration = DEFAULT_CLOCK_TOLERANCE;

/// How often `OcspChecker` repeats a query after an OCSP status error: a transport
/// failure or an answer other than `successful` (A_30044 (4), A_30046 (3) of C_12791).
pub const OCSP_STATUS_RETRIES: u32 = 3;

/// How long `OcspChecker` leaves a responder alone once the query and all its
/// repetitions failed (A_30044 (4), A_30046 (3) of C_12791).
pub const OCSP_STATUS_PAUSE: Duration = Duration::from_secs(300);

/// How long `OcspChecker` reuses a `good` or `revoked` result, at most until the
/// response's `nextUpdate` (A_30046 (6) of C_12791, after A_23225: one hour by default).
pub const OCSP_CACHE_TTL: Duration = Duration::from_secs(3600);

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
    /// The trust store whose intermediates may authorize a delegate of another CA of
    /// the issuing CA's TSP. Without it, only RFC 6960 authorization applies.
    pub store: Option<&'a TrustStore>,
    /// The response came with the object being checked (embedded in a signature, sent
    /// in an ASL handshake): it must be valid at `now`, the reference time
    /// (`thisUpdate` ≤ `now` ≤ `nextUpdate`), without tolerance or maximum age, and an
    /// eGK certificate needs no certHash (A_30046 (7) of C_12791).
    pub stapled: bool,
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
            store: None,
            stapled: false,
        }
    }

    /// The check of a response supplied with the object, at the `reference` time.
    pub fn stapled(reference: Timestamp, algorithms: &'a AlgorithmSet) -> Self {
        ResponseCheck {
            stapled: true,
            ..ResponseCheck::new(reference, algorithms)
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
            .with_defect(ResponseDefect::WrongCertificate)
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
    let authorization = match responder {
        Some(responder) => authorize(responder, issuer, check)
            .map_err(|message| ValidationError::new(ErrorCode::OcspResponderUntrusted, message))?,
        None => ResponderAuthorization::Issuer,
    };
    let signer = responder.unwrap_or(issuer);
    verify_signature(signer, &basic, &tbs_der, check.algorithms).map_err(|reason| {
        invalid(format!(
            "OCSP response signature does not verify under {:?}: {reason}",
            signer.subject_cn()
        ))
        .with_defect(ResponseDefect::Signature)
    })?;
    // An "unknown" answer has no certificate to vouch for, so it carries no certHash;
    // its status stands (A_30046 (2)).
    if !matches!(single.cert_status, CertStatus::Unknown(_)) {
        verify_cert_hash(
            single.single_extensions.as_ref(),
            cert,
            check.allow_missing_cert_hash || (check.stapled && is_egk(cert)),
        )
        .map_err(|(defect, message)| invalid(message).with_defect(defect))?;
    }

    let mut result = RevocationResult::unknown(check.now, "");
    result.produced_at = Some(data.produced_at.0);
    result.this_update = Some(single.this_update.0);
    result.next_update = single.next_update.map(|t| t.0);
    result.responder = responder.cloned();
    result.authorization = Some(authorization);
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
        CertStatus::Unknown(_) => UNKNOWN_STATUS.clone_into(&mut result.reason),
    }
    result
}

/// The reason of a result whose responder answered `unknown`, as opposed to one that is
/// unknown because the response lies outside the time window.
pub(crate) const UNKNOWN_STATUS: &str = "OCSP status: unknown";

/// What exactly made [`verify_response`] reject a response as
/// [`ErrorCode::OcspResponseInvalid`], kept on the error for the finer result codes of
/// the TSL signer's status (`spec/tsl-xmldsig` TSLSIG-041, 042).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponseDefect {
    /// No single response is about the certificate asked about.
    WrongCertificate,
    /// The response signature does not verify.
    Signature,
    /// The certHash extension is missing.
    CertHashMissing,
    /// The certHash does not hash the certificate, or cannot be read.
    CertHashMismatch,
}

impl ValidationError {
    pub(crate) fn with_defect(mut self, defect: ResponseDefect) -> Self {
        self.defect = Some(defect);
        self
    }
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
) -> Result<ResponderAuthorization, String> {
    if responder.subject_der() == issuer.subject_der()
        && responder.public_key() == issuer.public_key()
    {
        return Ok(ResponderAuthorization::Issuer);
    }
    let (name, ca) = (responder.subject_cn(), issuer.subject_cn());
    if responder.issuer_der() == issuer.subject_der() {
        responder
            .verify_signed_by(issuer, check.algorithms)
            .map_err(|e| {
                format!(
                    "OCSP responder {name:?} names the issuing CA {ca:?} as its issuer, but its \
                 certificate does not verify under the CA's key: {e}"
                )
            })?;
        delegate_usable(responder, check).map_err(|reason| {
            format!("OCSP responder {name:?}, certified by the issuing CA {ca:?}, {reason}")
        })?;
        return Ok(ResponderAuthorization::Delegate);
    }
    let not_rfc6960 = format!(
        "OCSP responder {name:?} was certified by {:?}, but the certificate was issued by \
         {ca:?}; RFC 6960 accepts only the issuing CA or a responder it certified directly",
        responder.issuer_cn()
    );
    let Some(store) = check.store else {
        return Err(format!(
            "{not_rfc6960}, and no trust store is at hand to accept a delegate of the same TSP"
        ));
    };
    let (ca, tsp) = same_tsp_delegate(responder, issuer, store, check).map_err(|reason| {
        format!("{not_rfc6960}; nor is it a delegate of the same TSP: {reason}")
    })?;
    // The TSL ties a responder to CAs only by its TSP: listed under the issuing CA's.
    Ok(
        if store.listed_responder_tsps(responder).any(|t| t == tsp) {
            ResponderAuthorization::TslListed { ca, tsp }
        } else {
            ResponderAuthorization::SameTspDelegate { ca, tsp }
        },
    )
}

/// What RFC 6960 asks of any delegate: id-kp-OCSPSigning, and validity now.
fn delegate_usable(responder: &Certificate, check: &ResponseCheck<'_>) -> Result<(), String> {
    if !responder.ext_key_usage().contains(&ID_KP_OCSP_SIGNING) {
        return Err("lacks id-kp-OCSPSigning".into());
    }
    let skew = check.clock_tolerance.as_secs();
    let valid = responder.is_valid_at(Timestamp(check.now.0.saturating_add(skew)))
        || responder.is_valid_at(Timestamp(check.now.0.saturating_sub(skew)));
    if !valid {
        return Err(format!(
            "is not valid at {} (valid {} to {})",
            check.now,
            responder.not_before(),
            responder.not_after()
        ));
    }
    Ok(())
}

/// The TI's responder model: a delegate usable under RFC 6960 rules, certified
/// (signature verified) by a TSL CA that a root signed, whose TSP is the issuing CA's.
/// Returns that CA's common name and the TSP; whether the TSL also lists the responder
/// decides between a listed responder and a mere delegate of the same TSP.
fn same_tsp_delegate(
    responder: &Certificate,
    issuer: &Certificate,
    store: &TrustStore,
    check: &ResponseCheck<'_>,
) -> Result<(String, String), String> {
    delegate_usable(responder, check).map_err(|reason| format!("it {reason}"))?;
    let responder_ca = store
        .intermediates()
        .iter()
        .find(|ca| {
            ca.subject_der() == responder.issuer_der()
                && responder.verify_signed_by(ca, check.algorithms).is_ok()
        })
        .ok_or_else(|| {
            format!(
                "{:?} is not a TSL CA under the trusted roots whose signature on it verifies",
                responder.issuer_cn()
            )
        })?;
    let issuer_tsp = store
        .provider_of(issuer)
        .ok_or_else(|| format!("the issuing CA {:?} is not a TSL CA", issuer.subject_cn()))?;
    let responder_tsp = store.provider_of(responder_ca).unwrap_or_default();
    if responder_tsp != issuer_tsp {
        return Err(format!(
            "{:?} belongs to TSP {responder_tsp:?}, the issuing CA to {issuer_tsp:?}",
            responder_ca.subject_cn()
        ));
    }
    Ok((responder_ca.subject_cn().to_owned(), issuer_tsp.to_owned()))
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
) -> Result<(), (ResponseDefect, String)> {
    let mismatch = |message: String| (ResponseDefect::CertHashMismatch, message);
    let Some(extension) = extensions
        .into_iter()
        .flatten()
        .find(|e| e.extn_id == CERT_HASH)
    else {
        return if allow_missing {
            Ok(())
        } else {
            Err((
                ResponseDefect::CertHashMissing,
                "OCSP response carries no certHash extension".into(),
            ))
        };
    };
    let cert_hash = CertHash::from_der(extension.extn_value.as_bytes())
        .map_err(|e| mismatch(format!("OCSP certHash extension is malformed: {e}")))?;
    let algorithm = cert_hash.hash_algorithm.oid;
    let expected = digest(&algorithm, cert.der()).ok_or_else(|| {
        mismatch(format!(
            "OCSP certHash uses unsupported hash algorithm {algorithm}"
        ))
    })?;
    if expected != cert_hash.certificate_hash.as_bytes() {
        return Err(mismatch(
            "OCSP certHash does not match the certificate".into(),
        ));
    }
    Ok(())
}

/// The TUC_PKI_006 window: `producedAt` within `[now - max age, now + tolerance]`,
/// `thisUpdate` at most the tolerance in the future, `nextUpdate` (if set) at most the
/// tolerance in the past. `None` inside it.
fn outside_window(result: &RevocationResult, check: &ResponseCheck<'_>) -> Option<String> {
    if check.stapled {
        let this_update = result.this_update?;
        if this_update > check.now {
            return Some(format!(
                "OCSP thisUpdate {this_update} lies after the reference time {}",
                check.now
            ));
        }
        if let Some(next_update) = result.next_update
            && next_update < check.now
        {
            return Some(format!(
                "OCSP nextUpdate {next_update} lies before the reference time {}",
                check.now
            ));
        }
        return None;
    }
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

/// An eGK certificate: of a `C.CH.*` type, or untyped with the Versicherter role.
fn is_egk(cert: &Certificate) -> bool {
    use crate::cert_type::{CertificateType as T, detect_certificate_type};
    matches!(
        detect_certificate_type(cert),
        Some(T::ChQes | T::ChSig | T::ChEnc | T::ChEncv | T::ChAut | T::ChAutn)
    ) || cert
        .admission()
        .ok()
        .flatten()
        .is_some_and(|a| a.profession_oids.contains(&crate::oid::PROF_VERSICHERTER))
}

/// Whether `der` is an OCSP response with a single response about `cert`.
fn answers_for(der: &[u8], cert: &Certificate, issuer: &Certificate) -> bool {
    let answers = || -> Option<bool> {
        let response = OcspResponse::from_der(der).ok()?;
        let bytes = response.response_bytes?;
        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).ok()?;
        let tbs = basic.tbs_response_data.to_der().ok()?;
        let data = ResponseData::from_der(&tbs).ok()?;
        Some(
            data.responses
                .iter()
                .any(|single| cert_id_matches(&single.cert_id, cert, issuer).is_ok()),
        )
    };
    answers().unwrap_or(false)
}

/// Answers revocation questions from OCSP responses supplied with the object being
/// checked (embedded in a signature, sent in an ASL handshake) instead of asking a
/// responder: the one about the certificate is verified at the reference time as
/// [`ResponseCheck::stapled`] describes (A_30046 (7) of C_12791). A certificate none of
/// them answers for is [`Unknown`](RevocationStatus::Unknown).
#[derive(Clone, Debug)]
pub struct StapledOcsp {
    responses: Vec<Vec<u8>>,
    reference: Timestamp,
    algorithms: std::borrow::Cow<'static, AlgorithmSet>,
}

impl StapledOcsp {
    /// Checks against `responses` at `reference`, verifying signatures with
    /// `algorithms` (usually the configuration's).
    pub fn new(
        responses: impl IntoIterator<Item = Vec<u8>>,
        reference: Timestamp,
        algorithms: std::borrow::Cow<'static, AlgorithmSet>,
    ) -> Self {
        StapledOcsp {
            responses: responses.into_iter().collect(),
            reference,
            algorithms,
        }
    }
}

impl RevocationChecker for StapledOcsp {
    async fn check(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        store: &TrustStore,
    ) -> Result<RevocationResult, ValidationError> {
        let check = ResponseCheck {
            store: Some(store),
            ..ResponseCheck::stapled(self.reference, &self.algorithms)
        };
        match self
            .responses
            .iter()
            .find(|der| answers_for(der, cert, issuer))
        {
            Some(der) => verify_response(der, cert, issuer, &check),
            None => Ok(RevocationResult::unknown(
                self.reference,
                "no supplied OCSP response answers for this certificate",
            )),
        }
    }
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
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, PoisonError};

    use der::Decode as _;

    use super::{
        CONTENT_TYPE_REQUEST, CONTENT_TYPE_RESPONSE, DEFAULT_MAX_RESPONSE_AGE, OCSP_CACHE_TTL,
        OCSP_STATUS_PAUSE, OCSP_STATUS_RETRIES, OcspResponse, ResponseCheck, ResponseStatus,
        request, verify_response,
    };
    use crate::algorithms::AlgorithmSet;
    use crate::error::{ErrorCode, ValidationError};
    use crate::load::{PostRequest, Transport};
    use crate::revocation::{RevocationChecker, RevocationResult, RevocationStatus};
    use crate::time::{Clock, Timestamp};
    use crate::{Certificate, TrustConfig, TrustStore};

    /// Results with the instant they expire, keyed by the DER request: its CertID names
    /// the certificate and its issuer.
    type ResultCache = HashMap<Vec<u8>, (RevocationResult, Timestamp)>;

    /// Queries a certificate's OCSP responder through a [`Transport`] and verifies the
    /// answer with [`verify_response`](super::verify_response). The transport owns
    /// timeouts and proxies. An OCSP status error (the transport failed, or the
    /// responder answered `tryLater`, `internalError` and the like) is repeated up to
    /// [`OCSP_STATUS_RETRIES`] times; after that the responder rests for
    /// [`OCSP_STATUS_PAUSE`], shared by the checker's clones.
    ///
    /// `good` and `revoked` results are reused for [`OCSP_CACHE_TTL`], at most until the
    /// response's `nextUpdate`; the cache is shared by the clones too. An `unknown` result
    /// or an error is never cached.
    #[derive(Clone, Debug)]
    pub struct OcspChecker<T, C> {
        transport: T,
        clock: C,
        algorithms: Cow<'static, AlgorithmSet>,
        clock_tolerance: core::time::Duration,
        max_response_age: core::time::Duration,
        allow_missing_cert_hash: bool,
        responder_url: Option<String>,
        resting: Arc<Mutex<HashMap<String, Timestamp>>>,
        cache_ttl: core::time::Duration,
        cache: Arc<Mutex<ResultCache>>,
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
                resting: Arc::default(),
                cache_ttl: OCSP_CACHE_TTL,
                cache: Arc::default(),
            }
        }

        /// Reuses `good` and `revoked` results for `ttl` instead of [`OCSP_CACHE_TTL`];
        /// zero turns the cache off.
        #[must_use]
        pub fn with_cache_ttl(mut self, ttl: core::time::Duration) -> Self {
            self.cache_ttl = ttl;
            self
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

        fn cached(&self, key: &[u8], now: Timestamp) -> Option<RevocationResult> {
            let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            match cache.get(key) {
                Some((result, until)) if *until > now => Some(result.clone()),
                Some(_) => {
                    cache.remove(key);
                    None
                }
                None => None,
            }
        }

        fn remember(&self, key: Vec<u8>, result: &RevocationResult, now: Timestamp) {
            if self.cache_ttl.is_zero()
                || !matches!(
                    result.status,
                    RevocationStatus::Good | RevocationStatus::Revoked
                )
            {
                return;
            }
            let ttl_end = Timestamp(now.0 + self.cache_ttl.as_secs());
            let until = result.next_update.map_or(ttl_end, |next| next.min(ttl_end));
            if until > now {
                self.cache
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(key, (result.clone(), until));
            }
        }

        /// When the responder at `url` may be asked again, if it is resting.
        fn resting_until(&self, url: &str, now: Timestamp) -> Option<Timestamp> {
            let mut resting = self.resting.lock().unwrap_or_else(PoisonError::into_inner);
            match resting.get(url) {
                Some(&until) if until > now => Some(until),
                Some(_) => {
                    resting.remove(url);
                    None
                }
                None => None,
            }
        }

        fn rest(&self, url: &str, until: Timestamp) {
            self.resting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(url.to_owned(), until);
        }

        /// POSTs `body` to `url` until an answer is `successful`, at most
        /// 1 + [`OCSP_STATUS_RETRIES`] times. The error is the last attempt's.
        async fn query(
            &self,
            url: &str,
            body: &[u8],
            cert: &Certificate,
        ) -> Result<Vec<u8>, ValidationError> {
            let mut failure = None;
            for _ in 0..=OCSP_STATUS_RETRIES {
                let posted = self
                    .transport
                    .post(&PostRequest {
                        url,
                        content_type: CONTENT_TYPE_REQUEST,
                        accept: CONTENT_TYPE_RESPONSE,
                        body,
                    })
                    .await;
                failure = Some(match posted {
                    Ok(answer) => match OcspResponse::from_der(&answer) {
                        Ok(r) if r.response_status == ResponseStatus::Successful => {
                            return Ok(answer);
                        }
                        Ok(r) => ValidationError::new(
                            ErrorCode::OcspUnavailable,
                            format!("OCSP responder {url} answered {:?}", r.response_status),
                        ),
                        Err(e) => ValidationError::new(
                            ErrorCode::OcspUnavailable,
                            format!("OCSP responder {url} sent no OCSP response"),
                        )
                        .with_cause(e),
                    },
                    Err(e) => ValidationError::new(
                        ErrorCode::OcspUnavailable,
                        format!("OCSP responder {url} unreachable"),
                    )
                    .with_cause(e),
                });
            }
            let until = Timestamp(self.clock.now().0 + OCSP_STATUS_PAUSE.as_secs());
            self.rest(url, until);
            let failure = failure.expect("at least one attempt was made");
            Err(ValidationError {
                message: format!(
                    "{} ({} attempts; resting until {until})",
                    failure.message,
                    OCSP_STATUS_RETRIES + 1
                ),
                ..failure
            }
            .with_subject(cert.subject_cn()))
        }
    }

    impl<T: Transport, C: Clock> RevocationChecker for OcspChecker<T, C> {
        /// No responder URL is an [`Unknown`](crate::revocation::RevocationStatus::Unknown)
        /// result: no other source could answer for such a certificate either. An OCSP
        /// status error that outlasts the repetitions, and any query while the
        /// responder rests, is [`ErrorCode::OcspUnavailable`].
        async fn check(
            &self,
            cert: &Certificate,
            issuer: &Certificate,
            store: &TrustStore,
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
            if let Some(result) = self.cached(&body, self.clock.now()) {
                return Ok(result);
            }
            if let Some(until) = self.resting_until(url, self.clock.now()) {
                return Err(ValidationError::new(
                    ErrorCode::OcspUnavailable,
                    format!("OCSP responder {url} rests until {until} after repeated failures"),
                )
                .with_subject(cert.subject_cn()));
            }
            let response = self.query(url, &body, cert).await?;
            let check = ResponseCheck {
                now: self.clock.now(),
                max_response_age: self.max_response_age,
                clock_tolerance: self.clock_tolerance,
                allow_missing_cert_hash: self.allow_missing_cert_hash,
                algorithms: &self.algorithms,
                store: Some(store),
                stapled: false,
            };
            let mut result = verify_response(&response, cert, issuer, &check)?;
            url.clone_into(&mut result.responder_url);
            self.remember(body, &result, check.now);
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

    #[cfg(feature = "brainpool")]
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
    #[cfg(feature = "brainpool")]
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

        /// A_30046 (2): an unknown answer needs no certHash, even where one is required.
        #[test]
        fn unknown_without_cert_hash() {
            let pki = TestPki::new();
            let result = verify(
                response!("unknown-no-cert-hash"),
                &pki.ee_arzt,
                &pki.sub_ca_hba,
            )
            .unwrap();
            assert_eq!(result.status, RevocationStatus::Unknown);
            assert_eq!(result.reason, "OCSP status: unknown");
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
                     responder it certified directly, and no trust store is at hand to \
                     accept a delegate of the same TSP",
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

        fn store_with(pki: &TestPki, cas: &[(&Certificate, &str)]) -> TrustStore {
            TrustStore::new([pki.rca1.clone(), pki.rca7.clone()]).with_intermediates(
                cas.iter()
                    .map(|(ca, tsp)| crate::tsl::Intermediate {
                        certificate: (*ca).clone(),
                        provider: (*tsp).to_owned(),
                    })
                    .collect(),
            )
        }

        /// ocsp-signer-komp, certified by GEM.SubCA-Komp, answers for a certificate of
        /// GEM.SubCA-HBA: not RFC 6960, acceptable only if both CAs share a TSP.
        #[test]
        fn delegates_of_the_same_tsp() {
            let pki = TestPki::new();
            let (hba, komp) = (&pki.sub_ca_hba, &pki.sub_ca_komp);
            let verify_with = |store: &TrustStore| {
                let check = ResponseCheck {
                    store: Some(store),
                    ..ResponseCheck::new(TestPki::NOW, algorithms::DEFAULT)
                };
                verify_response(response!("foreign-responder"), &pki.ee_arzt, hba, &check)
            };

            let same = verify_with(&store_with(&pki, &[(hba, "TSP A"), (komp, "TSP A")])).unwrap();
            assert_eq!(same.status, RevocationStatus::Good);
            assert_eq!(
                same.authorization,
                Some(ResponderAuthorization::SameTspDelegate {
                    ca: "GEM.SubCA-Komp TEST-ONLY".into(),
                    tsp: "TSP A".into(),
                })
            );

            // Listed by the TSL as an OCSP service of the issuing CA's TSP: authorized as
            // gemSpec_PKI does. Listed under another TSP: only the same-TSP fallback.
            let responder = crate::parse_pem_certificates(
                include_str!("../tests/pki/ocsp-signer-komp.pem").as_bytes(),
            )
            .unwrap()
            .remove(0);
            let listed = |tsp: &str| {
                store_with(&pki, &[(hba, "TSP A"), (komp, "TSP A")])
                    .with_listed_responders(vec![(responder.clone(), tsp.to_owned())])
            };
            assert_eq!(
                verify_with(&listed("TSP A")).unwrap().authorization,
                Some(ResponderAuthorization::TslListed {
                    ca: "GEM.SubCA-Komp TEST-ONLY".into(),
                    tsp: "TSP A".into(),
                })
            );
            assert!(matches!(
                verify_with(&listed("TSP B")).unwrap().authorization,
                Some(ResponderAuthorization::SameTspDelegate { .. })
            ));
            // A listing never replaces the certification by a CA of the same TSP.
            let other_tsp = store_with(&pki, &[(hba, "TSP A"), (komp, "TSP B")])
                .with_listed_responders(vec![(responder.clone(), "TSP A".to_owned())]);
            assert!(verify_with(&other_tsp).is_err());
            let uncertified = store_with(&pki, &[(hba, "TSP A")])
                .with_listed_responders(vec![(responder, "TSP A".to_owned())]);
            assert!(verify_with(&uncertified).is_err());

            for (store, reason) in [
                (
                    store_with(&pki, &[(hba, "TSP A"), (komp, "TSP B")]),
                    "\"GEM.SubCA-Komp TEST-ONLY\" belongs to TSP \"TSP B\", the issuing CA to \
                     \"TSP A\"",
                ),
                (
                    store_with(&pki, &[(hba, "TSP A")]),
                    "\"GEM.SubCA-Komp TEST-ONLY\" is not a TSL CA under the trusted roots \
                     whose signature on it verifies",
                ),
                (
                    store_with(&pki, &[(komp, "TSP A")]),
                    "the issuing CA \"GEM.SubCA-HBA TEST-ONLY\" is not a TSL CA",
                ),
            ] {
                let error = verify_with(&store).unwrap_err();
                assert_eq!(error.code, ErrorCode::OcspResponderUntrusted);
                assert!(
                    error
                        .message
                        .ends_with(&format!("nor is it a delegate of the same TSP: {reason}")),
                    "{error}"
                );
            }
        }

        #[test]
        fn rfc6960_authorizations_are_recorded() {
            let pki = TestPki::new();
            let direct = verify(response!("good"), &pki.ee_arzt, &pki.sub_ca_hba).unwrap();
            assert_eq!(direct.authorization, Some(ResponderAuthorization::Delegate));
            let by_ca = verify(response!("issuer-signed"), &pki.sub_ca_hba, &pki.rca1).unwrap();
            assert_eq!(by_ca.authorization, Some(ResponderAuthorization::Issuer));
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

        /// A_30046 (7): a supplied response is valid at the reference time, without
        /// tolerance or maximum age.
        #[test]
        fn stapled_responses_at_a_reference_time() {
            let pki = TestPki::new();
            let (ee, ca) = (&pki.ee_arzt, &pki.sub_ca_hba);
            let stapled = |reference: Timestamp| {
                verify_response(
                    response!("good"),
                    ee,
                    ca,
                    &ResponseCheck::stapled(reference, algorithms::DEFAULT),
                )
                .unwrap()
            };
            let hours_later = Timestamp(TestPki::NOW.0 + 3 * 3600);
            assert_eq!(stapled(hours_later).status, RevocationStatus::Good);
            assert_eq!(
                verify_at(response!("good"), ee, ca, hours_later)
                    .unwrap()
                    .status,
                RevocationStatus::Unknown,
                "too old for an online answer"
            );
            assert_eq!(
                stapled(Timestamp(TestPki::NOW.0 - 1)).reason,
                "OCSP thisUpdate 2026-01-01T00:00:00Z lies after the reference time \
                 2025-12-31T23:59:59Z"
            );
            assert_eq!(
                stapled(at("2026-01-02T00:00:01Z")).reason,
                "OCSP nextUpdate 2026-01-02T00:00:00Z lies before the reference time \
                 2026-01-02T00:00:01Z"
            );
        }

        /// A_30046 (7): an eGK certificate's supplied response needs no certHash; any
        /// other's does, and online answers always do.
        #[test]
        fn stapled_egk_responses_need_no_cert_hash() {
            let pki = TestPki::new();
            let egk = crate::testing::typed("type-ch-aut");
            let stapled = ResponseCheck::stapled(TestPki::NOW, algorithms::DEFAULT);
            let result = verify_response(
                response!("egk-no-cert-hash"),
                &egk,
                &pki.sub_ca_komp,
                &stapled,
            )
            .unwrap();
            assert_eq!(result.status, RevocationStatus::Good);
            let online = verify(response!("egk-no-cert-hash"), &egk, &pki.sub_ca_komp).unwrap_err();
            assert_eq!(
                online.message,
                "OCSP response carries no certHash extension"
            );
            let other = verify_response(
                response!("no-cert-hash"),
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &stapled,
            )
            .unwrap_err();
            assert_eq!(other.message, "OCSP response carries no certHash extension");
        }

        #[test]
        fn stapled_checker_picks_the_response_about_the_certificate() {
            let pki = TestPki::new();
            let store = TrustStore::new([pki.rca1.clone()]);
            let checker = StapledOcsp::new(
                [
                    response!("egk-no-cert-hash").to_vec(),
                    response!("good").to_vec(),
                ],
                TestPki::NOW,
                algorithms::DEFAULT.into(),
            );
            let check = |cert: &Certificate| {
                futures_lite::future::block_on(checker.check(cert, &pki.sub_ca_hba, &store))
                    .unwrap()
            };
            assert_eq!(check(&pki.ee_arzt).status, RevocationStatus::Good);
            let none = check(&pki.ee_revoked);
            assert_eq!(none.status, RevocationStatus::Unknown);
            assert_eq!(
                none.reason,
                "no supplied OCSP response answers for this certificate"
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
            let refused = || {
                Err(TransportError {
                    kind: TransportErrorKind::Network,
                    message: "connection refused".into(),
                    retryable: true,
                })
            };
            let transport = MockTransport::posting([
                Ok(response!("good").to_vec()),
                refused(),
                refused(),
                refused(),
                refused(),
            ]);
            let store = TrustStore::new([pki.rca1.clone()]);
            let checker = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW))
                .with_responder_url("http://ocsp.test/")
                .with_cache_ttl(Duration::ZERO);
            let result = futures_lite::future::block_on(checker.check(
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &store,
            ))
            .unwrap();
            assert_eq!(result.status, RevocationStatus::Good);
            assert_eq!(result.responder_url, "http://ocsp.test/");
            let posts = transport.posts();
            assert_eq!(posts[0].0, "http://ocsp.test/");
            assert_eq!(posts[0].1, request(&pki.ee_arzt, &pki.sub_ca_hba));

            let error = futures_lite::future::block_on(checker.check(
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &store,
            ))
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspUnavailable);
            assert_eq!(
                error.to_string(),
                "ti-pki[ocsp_unavailable]: OCSP responder http://ocsp.test/ unreachable \
                 (4 attempts; resting until 2026-01-01T00:05:00Z): \"Dr. Arzt TEST-ONLY\": \
                 network error: connection refused"
            );
            assert_eq!(transport.posts().len(), 5);

            let without_url = OcspChecker::new(&config, &transport, FixedClock::new(TestPki::NOW));
            let result = futures_lite::future::block_on(without_url.check(
                &pki.ee_arzt,
                &pki.sub_ca_hba,
                &store,
            ))
            .unwrap();
            assert_eq!(result.status, RevocationStatus::Unknown);
            assert!(result.reason.starts_with("no OCSP responder URL"));
        }

        /// A_30044 (4), A_30046 (3): an OCSP status error is repeated up to three times,
        /// then the responder rests for five minutes.
        #[cfg(feature = "load")]
        #[test]
        fn status_errors_are_repeated_then_the_responder_rests() {
            use crate::load::MockTransport;
            use crate::revocation::RevocationChecker;
            use crate::time::FixedClock;

            const TRY_LATER: [u8; 5] = [0x30, 0x03, 0x0a, 0x01, 0x03];
            let pki = TestPki::new();
            let config = crate::TrustConfig::for_anchor(pki.rca1.der().to_vec());
            let store = TrustStore::new([pki.rca1.clone()]);
            let try_later = || Ok(TRY_LATER.to_vec());
            let transport = MockTransport::posting([
                try_later(),
                try_later(),
                Ok(response!("good").to_vec()),
                try_later(),
                try_later(),
                try_later(),
                try_later(),
                Ok(response!("good").to_vec()),
            ]);
            let clock = FixedClock::new(TestPki::NOW);
            let checker = OcspChecker::new(&config, &transport, &clock)
                .with_responder_url("http://ocsp.test/")
                .with_cache_ttl(Duration::ZERO);
            let check = || {
                futures_lite::future::block_on(checker.check(&pki.ee_arzt, &pki.sub_ca_hba, &store))
            };

            assert_eq!(check().unwrap().status, RevocationStatus::Good);
            assert_eq!(transport.posts().len(), 3);

            let error = check().unwrap_err();
            assert_eq!(error.code, ErrorCode::OcspUnavailable);
            assert_eq!(
                error.message,
                "OCSP responder http://ocsp.test/ answered TryLater \
                 (4 attempts; resting until 2026-01-01T00:05:00Z)"
            );
            assert_eq!(transport.posts().len(), 7);

            clock.advance(Duration::from_secs(299));
            let resting = check().unwrap_err();
            assert_eq!(
                resting.message,
                "OCSP responder http://ocsp.test/ rests until 2026-01-01T00:05:00Z after \
                 repeated failures"
            );
            assert_eq!(
                transport.posts().len(),
                7,
                "a resting responder is not asked"
            );

            clock.advance(Duration::from_secs(1));
            // The answer is from NOW; five minutes on it is too old for the window.
            let result = check().unwrap();
            assert_eq!(transport.posts().len(), 8);
            assert_eq!(result.status, RevocationStatus::Unknown);
            assert!(
                result.reason.ends_with("more than the 37 s allowed"),
                "{}",
                result.reason
            );
        }

        /// A_30046 (6): good and revoked results are reused for an hour, at most until
        /// nextUpdate; unknown results and errors are not.
        #[cfg(feature = "load")]
        #[test]
        fn results_are_cached() {
            use crate::load::MockTransport;
            use crate::revocation::RevocationChecker;
            use crate::time::FixedClock;

            let pki = TestPki::new();
            let config = crate::TrustConfig::for_anchor(pki.rca1.der().to_vec());
            let store = TrustStore::new([pki.rca1.clone()]);
            let transport = MockTransport::posting([
                Ok(response!("good").to_vec()),
                Ok(response!("unknown").to_vec()),
                Ok(response!("unknown").to_vec()),
            ]);
            let clock = FixedClock::new(TestPki::NOW);
            let checker = OcspChecker::new(&config, &transport, &clock)
                .with_responder_url("http://ocsp.test/");
            let check = |ee: &Certificate| {
                futures_lite::future::block_on(checker.check(ee, &pki.sub_ca_hba, &store))
            };

            let first = check(&pki.ee_arzt).unwrap();
            assert_eq!(first.status, RevocationStatus::Good);
            clock.advance(Duration::from_secs(3599));
            assert_eq!(
                check(&pki.ee_arzt).unwrap(),
                first,
                "reused within the hour"
            );
            assert_eq!(transport.posts().len(), 1);

            clock.advance(Duration::from_secs(1));
            let after = check(&pki.ee_arzt).unwrap();
            assert_eq!(after.status, RevocationStatus::Unknown, "{}", after.reason);
            assert_eq!(transport.posts().len(), 2, "asked again after the hour");
            check(&pki.ee_arzt).unwrap();
            assert_eq!(
                transport.posts().len(),
                3,
                "an unknown result is not reused"
            );
        }
    }
}
