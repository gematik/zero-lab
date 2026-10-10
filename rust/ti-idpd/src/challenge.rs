//! The challenge–response at the authorization endpoint: fetching the challenge the
//! relying party's authorization URL yields, answering it with the card's signature,
//! and reading the code out of the redirect.

use jwz::header::HeaderParams;
use jwz::jwa::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm};
use jwz::jwe::{self, EncryptionKey};
use jwz::jwk::Jwk;
use jwz::jws::{self, Jws};
use jwz::jwt::{Claims, FixedClock};
use jwz::keys::Signer;
use serde_json::{Value, json};

use crate::discovery::{self, Metadata};
use crate::error::{Error, IdpError};
use crate::http::{Request, Response};
use crate::query;

/// What the IDP sent for an authorization request: the challenge to sign and what the
/// user is asked to consent to.
#[derive(Clone, Debug)]
pub struct Challenge {
    /// The `CHALLENGE_TOKEN`, a JWS by `PuK_IDP_SIG`, as received (it is signed over
    /// as is).
    pub token: String,
    /// `user_consent`: `requested_scopes` and `requested_claims`, as sent.
    pub user_consent: Value,
    /// The challenge's `exp`, which the response's JWE repeats.
    pub exp: u64,
    /// The challenge's claims (`client_id`, `state`, `nonce`, `scope`, …).
    pub claims: Value,
}

/// The request for the challenge: the relying party's authorization URL, fetched
/// without following redirects.
pub fn request(authorization_url: &str) -> Request {
    Request::get(authorization_url)
}

/// The challenge in `response`, verified with `puk_idp_sig` and valid at `now`.
///
/// # Errors
///
/// [`Error::Idp`] when the IDP refused (a `302` with `error`, or a JSON error body);
/// [`Error::Status`] for another status; [`Error::Jose`] if the challenge does not
/// verify or is not valid at `now`; [`Error::Malformed`] otherwise.
pub fn parse(response: &Response, puk_idp_sig: &Jwk, now: u64) -> Result<Challenge, Error> {
    if let Some(error) = refusal(response) {
        return Err(Error::Idp(error));
    }
    discovery::expect_ok("challenge", response)?;
    let body: Value =
        serde_json::from_slice(&response.body).map_err(|e| Error::malformed("challenge", e))?;
    let token = body
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::malformed("challenge", "no `challenge` member"))?
        .to_owned();
    let user_consent = body.get("user_consent").cloned().unwrap_or(Value::Null);
    let registry = ti_jwz::registry();
    let profile = ti_jwz::ti_legacy();
    let jws = Jws::parse(&token, &profile.policy, &registry).map_err(Error::jose("challenge"))?;
    let key = discovery::verifier_from_jwk(puk_idp_sig, jws.algorithm(), &registry)?;
    let verified = jws
        .verify(&key)
        .map_err(Error::jose("challenge signature"))?;
    let claims = Claims::parse(verified.payload()).map_err(Error::jose("challenge claims"))?;
    claims
        .validate(&profile.claims, &FixedClock(now))
        .map_err(Error::jose("challenge validity"))?;
    let exp = claims
        .exp()
        .map_err(Error::jose("challenge exp"))?
        .ok_or_else(|| Error::malformed("challenge", "no exp"))?;
    let claims: Value =
        serde_json::from_slice(verified.payload()).map_err(|e| Error::malformed("challenge", e))?;
    Ok(Challenge {
        token,
        user_consent,
        exp,
        claims,
    })
}

/// The IDP's error in a redirect's query, if the response is one.
fn refusal(response: &Response) -> Option<IdpError> {
    if !(300..400).contains(&response.status) {
        return None;
    }
    let location = response.header("location")?;
    IdpError::from_query(&query::pairs(location))
}

/// The answer to `challenge`: the nested JWT `{"njwt": challenge}` signed by `signer`
/// (`alg` the signer's, `BP256R1` for today's cards; `typ JWT`, `cty NJWT`, `x5c` the
/// AUT certificate `certificate_der`), wrapped as `{"njwt": …}` in a JWE for
/// `puk_idp_enc` (`ECDH-ES`, `A256GCM`, `cty NJWT`, `exp` of the challenge), posted
/// as `signed_challenge` to the authorization endpoint.
///
/// # Errors
///
/// [`Error::SignerAlgorithm`] if the signer's algorithm is not one the IDP accepts
/// (`BP256R1`); [`Error::Jose`] for a signing or encryption failure.
pub fn respond(
    challenge: &Challenge,
    signer: &dyn Signer,
    certificate_der: &[u8],
    puk_idp_enc: &Jwk,
    metadata: &Metadata,
) -> Result<Request, Error> {
    if signer.algorithm() != jwz_brainpool::BP256R1 {
        return Err(Error::SignerAlgorithm {
            found: signer.algorithm().as_str().to_owned(),
            needed: "BP256R1",
        });
    }
    let nested = json!({ "njwt": challenge.token });
    let params = HeaderParams::new()
        .typ("JWT")
        .cty("NJWT")
        .x5c(&[certificate_der]);
    let nested_jws = jws::sign(nested.to_string().as_bytes(), params, signer)
        .map_err(Error::jose("signed challenge"))?;
    let plaintext = json!({ "njwt": nested_jws }).to_string();
    let registry = ti_jwz::registry();
    let backend = discovery::backend();
    let params = HeaderParams::new()
        .cty("NJWT")
        .param("exp", Value::from(challenge.exp))
        .map_err(Error::jose("signed challenge header"))?;
    let encrypted = jwe::encrypt(
        plaintext.as_bytes(),
        KeyEncryptionAlgorithm::ECDH_ES,
        ContentEncryptionAlgorithm::A256GCM,
        EncryptionKey::Public(puk_idp_enc),
        params,
        &registry,
        backend.as_ref(),
    )
    .map_err(Error::jose("signed challenge encryption"))?;
    // A compact JWE is base64url and dots: nothing to percent-encode.
    Ok(Request::post_form(
        &metadata.authorization_endpoint,
        format!("signed_challenge={encrypted}"),
    ))
}

/// Where the IDP sends the user after the challenge was answered: the relying party's
/// redirect URI with the authorization code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeRedirect {
    /// The `Location` as sent.
    pub url: String,
    /// `code`.
    pub code: String,
    /// `state`, when the relying party sent one.
    pub state: Option<String>,
}

/// The code in the `302` that answers [`respond`]'s request.
///
/// # Errors
///
/// [`Error::Idp`] when the redirect or the body carries the IDP's error;
/// [`Error::Status`] for a status that is not a redirect; [`Error::Malformed`] for a
/// redirect without `code`.
pub fn code(response: &Response) -> Result<CodeRedirect, Error> {
    if let Some(error) = refusal(response) {
        return Err(Error::Idp(error));
    }
    if !(300..400).contains(&response.status) {
        return Err(IdpError::from_body(response.status, &response.body).map_or(
            Error::Status {
                what: "signed challenge",
                status: response.status,
            },
            Error::Idp,
        ));
    }
    let url = response
        .header("location")
        .ok_or_else(|| Error::malformed("code redirect", "no Location"))?
        .to_owned();
    let pairs = query::pairs(&url);
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let code =
        get("code").ok_or_else(|| Error::malformed("code redirect", "no code in Location"))?;
    Ok(CodeRedirect {
        state: get("state"),
        url,
        code,
    })
}
