//! The IDP's signed discovery document and its two public keys.

use std::sync::Arc;

use jwz::crypto::Extended;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::SignatureAlgorithm;
use jwz::jwk::{EcKey, Jwk, KeyMaterial};
use jwz::jws::Jws;
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::SoftwareKey;
use jwz::profile::ClaimsPolicy;
use serde::Deserialize;
use ti_pki::Certificate;

use crate::error::{Error, IdpError};
use crate::http::{Request, Response};
use crate::{Idp, Warning};

/// The brainpool-capable backend every verification and encryption here runs on.
pub(crate) type Backend = Extended<RustCrypto>;

pub(crate) fn backend() -> Arc<Backend> {
    Arc::new(jwz_brainpool::backend(RustCrypto::new()))
}

/// The OpenID metadata of an IDP-Dienst (gemSpec_IDP_Dienst §7.2): the standard
/// members a client needs and the IDP's own key URIs. Unknown members are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct Metadata {
    /// `issuer`.
    pub issuer: String,
    /// `authorization_endpoint`: where the challenge is fetched and answered.
    pub authorization_endpoint: String,
    /// `token_endpoint`: the relying party's side.
    pub token_endpoint: String,
    /// `uri_puk_idp_sig`: the key the challenge, the code and the tokens are signed with.
    pub uri_puk_idp_sig: String,
    /// `uri_puk_idp_enc`: the key the signed challenge and the key verifier are
    /// encrypted to.
    pub uri_puk_idp_enc: String,
    /// `jwks_uri`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// `sso_endpoint`, for SSO tokens (not used here).
    #[serde(default)]
    pub sso_endpoint: Option<String>,
    /// `uri_pair`, the pairing endpoint of alternative authentication (not used here).
    #[serde(default)]
    pub uri_pair: Option<String>,
    /// `alternative_authorization_endpoint` (not used here).
    #[serde(default)]
    pub alternative_authorization_endpoint: Option<String>,
    /// `scopes_supported`.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// The verified discovery document.
#[derive(Clone, Debug)]
pub struct Discovery {
    /// The metadata.
    pub metadata: Metadata,
    /// The signer's certificate (the `x5c` leaf), DER, for a later check against the
    /// TSL.
    pub signer_der: Vec<u8>,
    /// The signer's `kid`, `puk_disc_sig`.
    pub kid: Option<String>,
    /// What was not proven.
    pub warnings: Vec<Warning>,
}

/// The request for `idp`'s discovery document.
pub fn request(idp: &Idp) -> Request {
    Request::get(&format!(
        "{}/.well-known/openid-configuration",
        idp.base_url()
    ))
}

/// The document in `response`, its signature verified with the certificate it carries
/// and its validity checked at `now` (seconds since the epoch).
///
/// # Errors
///
/// [`Error::Idp`] or [`Error::Status`] for a non-200; [`Error::Jose`] if the JWS does
/// not parse under the TI profile or does not verify; [`Error::Malformed`] for a
/// payload that is not the metadata.
pub fn parse(response: &Response, now: u64) -> Result<Discovery, Error> {
    expect_ok("discovery document", response)?;
    let token = std::str::from_utf8(&response.body)
        .map_err(|e| Error::malformed("discovery document", e))?
        .trim();
    let registry = ti_jwz::registry();
    let profile = ti_jwz::ti_legacy();
    let jws =
        Jws::parse(token, &profile.policy, &registry).map_err(Error::jose("discovery document"))?;
    let chain = jws
        .header()
        .x5c()
        .map_err(Error::jose("discovery document x5c"))?
        .ok_or_else(|| Error::malformed("discovery document", "no x5c: the signer is unknown"))?;
    let leaf = chain
        .first()
        .ok_or_else(|| Error::malformed("discovery document", "empty x5c"))?;
    let certificate =
        Certificate::from_der(leaf).map_err(|e| Error::malformed("discovery document x5c", e))?;
    let kid = jws.header().kid().map(str::to_owned);
    let key = verifier_from_certificate(&certificate, jws.algorithm(), &registry)?;
    let verified = jws
        .verify(&key)
        .map_err(Error::jose("discovery document signature"))?;
    let claims =
        Claims::parse(verified.payload()).map_err(Error::jose("discovery document claims"))?;
    claims
        .validate(&discovery_claims(&profile.claims), &FixedClock(now))
        .map_err(Error::jose("discovery document validity"))?;
    let metadata: Metadata = serde_json::from_slice(verified.payload())
        .map_err(|e| Error::malformed("discovery document", e))?;
    Ok(Discovery {
        metadata,
        signer_der: leaf.clone(),
        kid,
        warnings: vec![Warning::IdpCertificatesUnverified],
    })
}

/// The TI claims policy for the IDP's own tokens: `exp` required, 60 s leeway.
fn discovery_claims(policy: &ClaimsPolicy) -> ClaimsPolicy {
    policy.clone()
}

/// A verifier for `alg` from the public key of `certificate`: the curve is the
/// certificate's, `alg` must name it.
pub(crate) fn verifier_from_certificate(
    certificate: &Certificate,
    alg: SignatureAlgorithm,
    registry: &jwz::jwa::Registry,
) -> Result<SoftwareKey<Backend>, Error> {
    let crv = if alg == jwz_brainpool::BP256R1 {
        "BP-256"
    } else {
        "P-256"
    };
    let jwk = Jwk::new(KeyMaterial::Ec(EcKey::from_point(
        crv,
        certificate.public_key(),
    )));
    SoftwareKey::from_jwk(&jwk, alg, registry, backend()).map_err(Error::jose("signer key"))
}

/// A verifier for `alg` from a public JWK, as the IDP publishes `PuK_IDP_SIG`.
pub(crate) fn verifier_from_jwk(
    jwk: &Jwk,
    alg: SignatureAlgorithm,
    registry: &jwz::jwa::Registry,
) -> Result<SoftwareKey<Backend>, Error> {
    // The IDP's JWK names `BP256R1` or nothing; a `use`/`alg` that disagrees is refused
    // by jwz.
    SoftwareKey::from_jwk(jwk, alg, registry, backend()).map_err(Error::jose("PuK_IDP_SIG"))
}

/// The request for one of the IDP's keys (`uri_puk_idp_sig`, `uri_puk_idp_enc`).
pub fn key_request(uri: &str) -> Request {
    Request::get(uri)
}

/// The JWK in `response`, checked against the TI registry (an EC key on `BP-256` or
/// `P-256`).
///
/// # Errors
///
/// [`Error::Idp`] or [`Error::Status`] for a non-200; [`Error::Jose`] for a JWK that
/// does not parse or names an unknown curve.
pub fn parse_key(what: &'static str, response: &Response) -> Result<Jwk, Error> {
    expect_ok(what, response)?;
    let text = std::str::from_utf8(&response.body).map_err(|e| Error::malformed(what, e))?;
    let jwk = Jwk::parse(text).map_err(Error::jose(what))?;
    jwk.check(&ti_jwz::registry()).map_err(Error::jose(what))?;
    if jwk.key_type() != jwz::jwa::KeyType::EC {
        return Err(Error::malformed(what, "not an EC key"));
    }
    Ok(jwk)
}

/// 200, or the IDP's error.
pub(crate) fn expect_ok(what: &'static str, response: &Response) -> Result<(), Error> {
    match response.status {
        200 => Ok(()),
        status => Err(IdpError::from_body(status, &response.body)
            .map_or(Error::Status { what, status }, Error::Idp)),
    }
}
