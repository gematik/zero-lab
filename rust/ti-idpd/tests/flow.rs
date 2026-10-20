/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 */

//! The Authenticator-Modul flow against an in-memory IDP-Dienst that signs with the
//! TEST-ONLY signer of `fixtures/` and answers as gemSpec_IDP_Dienst describes
//! (`tokenFlowPs` of gematik's reference implementation): discovery, keys, challenge,
//! signed challenge, code. The card identity is a generated BP256R1 key.

use std::cell::RefCell;
use std::sync::Arc;

use jwz::crypto::Backend as _;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::jws;
use jwz::keys::{Signer, SoftwareAgreementKey, SoftwareKey};
use serde_json::{Value, json};
use ti_idpd::authenticator::{self, Identity};
use ti_idpd::http::{Method, Request, Response, Transport, TransportError};
use ti_idpd::trust::{CertificateTrust, Checked, IdpCertificate, Unverified};
use ti_idpd::{Error, Idp, Warning, challenge, discovery};
use ti_pki::Certificate;

/// The flow awaits only the signer, which answers at once here: one poll completes it.
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => panic!("a synchronous signer never leaves the flow pending"),
    }
}

const NOW: u64 = 1_760_000_000;
const AUTH_URL: &str = "https://idp.test/sign_response?client_id=gematikTestPs&response_type=code&redirect_uri=https%3A%2F%2Frp.test%2Fcb&state=s1&nonce=n1&scope=openid+e-rezept&code_challenge=abc&code_challenge_method=S256";

type Backend = jwz::crypto::Extended<RustCrypto>;

fn backend() -> Arc<Backend> {
    Arc::new(jwz_brainpool::backend(RustCrypto::new()))
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// The IDP's signing key from the fixture: the SEC1 key's scalar on the certificate's
/// point.
fn idp_sig_key(kid: &str) -> (SoftwareKey<Backend>, Vec<u8>) {
    let cert = ti_pki::parse_pem_certificates(&fixture("idpd-sig.pem"))
        .unwrap()
        .remove(0);
    let pem = fixture("idpd-sig.key");
    let (label, der) = pem_rfc7468::decode_vec(&pem).unwrap();
    assert_eq!(label, "EC PRIVATE KEY");
    let scalar = sec1::EcPrivateKey::try_from(der.as_slice())
        .unwrap()
        .private_key
        .to_vec();
    let mut material = EcKey::from_point("BP-256", cert.public_key());
    material.d = Some(Secret::new(scalar));
    let key = SoftwareKey::from_jwk(
        &Jwk::new(KeyMaterial::Ec(material)),
        jwz_brainpool::BP256R1,
        &ti_jwz::registry(),
        backend(),
    )
    .unwrap()
    .with_kid(kid);
    (key, cert.der().to_vec())
}

/// The card: a BP256R1 key and some AUT certificate for `x5c`.
fn card() -> (SoftwareKey<Backend>, Vec<u8>) {
    let key =
        SoftwareKey::generate(jwz_brainpool::BP256R1, &ti_jwz::registry(), backend()).unwrap();
    let cert =
        ti_pki::parse_pem_certificates(&fixture("../../../ti-cli/tests/fixtures/identity/aut.pem"))
            .unwrap()
            .remove(0);
    (key, cert.der().to_vec())
}

/// An IDP-Dienst in memory: what it serves, and what it saw.
struct FakeIdp {
    disc_sig: SoftwareKey<Backend>,
    disc_cert: Vec<u8>,
    idp_sig: SoftwareKey<Backend>,
    idp_sig_cert: Vec<u8>,
    /// `PuK_IDP_ENC` as published: the public JWK with its `kid`.
    idp_enc: Jwk,
    /// Tweaks for the failure cases.
    behaviour: Behaviour,
    posted: RefCell<Vec<String>>,
}

/// How the fake deviates from a well-behaved IDP, one way at a time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Behaviour {
    #[default]
    Normal,
    RefuseChallengeInRedirect,
    RefuseChallengeWithBody,
    ChallengeSignedByOtherKey,
    ChallengeExpired,
    DiscoveryWithoutX5c,
    IdpSigWithoutX5c,
    /// `PuK_IDP_SIG`'s `x5c` is a certificate for another key.
    IdpSigX5cOfOtherKey,
}

impl FakeIdp {
    fn new(behaviour: Behaviour) -> FakeIdp {
        let (disc_sig, disc_cert) = idp_sig_key("puk_disc_sig");
        let (idp_sig, idp_sig_cert) = idp_sig_key("puk_idp_sig");
        let mut idp_enc = SoftwareAgreementKey::generate(jwz_brainpool::BP_256, backend())
            .unwrap()
            .public_jwk();
        idp_enc.kid = Some("puk_idp_enc".into());
        FakeIdp {
            disc_sig,
            disc_cert,
            idp_sig,
            idp_sig_cert,
            idp_enc,
            behaviour,
            posted: RefCell::new(Vec::new()),
        }
    }

    fn metadata() -> Value {
        json!({
            "issuer": "https://idp.test",
            "authorization_endpoint": "https://idp.test/sign_response",
            "token_endpoint": "https://idp.test/token",
            "uri_puk_idp_sig": "https://idp.test/idpSig/jwk.json",
            "uri_puk_idp_enc": "https://idp.test/idpEnc/jwk.json",
            "jwks_uri": "https://idp.test/jwks",
            "sso_endpoint": "https://idp.test/sso_response",
            "scopes_supported": ["openid", "e-rezept"],
            "iat": NOW - 60,
            "exp": NOW + 86_400,
        })
    }

    fn discovery_document(&self) -> String {
        let mut params = HeaderParams::new().typ("JWT");
        if self.behaviour != Behaviour::DiscoveryWithoutX5c {
            params = params.x5c(&[&self.disc_cert]);
        }
        jws::sign(
            Self::metadata().to_string().as_bytes(),
            params,
            &self.disc_sig,
        )
        .unwrap()
    }

    fn challenge(&self) -> String {
        // Beyond the TI profile's 60 s leeway when expired.
        let exp = if self.behaviour == Behaviour::ChallengeExpired {
            NOW - 120
        } else {
            NOW + 180
        };
        let claims = json!({
            "iss": "https://idp.test", "iat": NOW - 1, "exp": exp,
            "token_type": "challenge", "jti": "j1", "snc": "snc1",
            "scope": "openid e-rezept", "code_challenge": "abc", "code_challenge_method": "S256",
            "response_type": "code", "redirect_uri": "https://rp.test/cb",
            "client_id": "gematikTestPs", "state": "s1", "nonce": "n1",
        });
        let other;
        let signer: &dyn Signer = if self.behaviour == Behaviour::ChallengeSignedByOtherKey {
            // A key that is not PuK_IDP_SIG, under its kid.
            other = SoftwareKey::generate(jwz_brainpool::BP256R1, &ti_jwz::registry(), backend())
                .unwrap()
                .with_kid("puk_idp_sig");
            &other
        } else {
            &self.idp_sig
        };
        jws::sign(
            claims.to_string().as_bytes(),
            HeaderParams::new().typ("JWT"),
            signer,
        )
        .unwrap()
    }

    fn respond(status: u16, headers: &[(&str, &str)], body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.into(),
        }
    }
}

impl Transport for FakeIdp {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let (path, _) = request.url.split_once('?').unwrap_or((&request.url, ""));
        Ok(match (request.method, path) {
            (Method::Get, "https://idp.test/.well-known/openid-configuration") => Self::respond(
                200,
                &[("content-type", "application/jwt")],
                self.discovery_document(),
            ),
            (Method::Get, "https://idp.test/idpSig/jwk.json") => {
                use base64ct::{Base64, Encoding};
                let mut jwk = self.idp_sig.public_jwk();
                jwk.x5c = match self.behaviour {
                    Behaviour::IdpSigWithoutX5c => None,
                    Behaviour::IdpSigX5cOfOtherKey => Some(vec![Base64::encode_string(&card().1)]),
                    _ => Some(vec![Base64::encode_string(&self.idp_sig_cert)]),
                };
                Self::respond(200, &[], jwk.to_json())
            }
            (Method::Get, "https://idp.test/idpEnc/jwk.json") => {
                Self::respond(200, &[], self.idp_enc.to_json())
            }
            (Method::Get, "https://idp.test/sign_response") => {
                if self.behaviour == Behaviour::RefuseChallengeInRedirect {
                    return Ok(Self::respond(
                        302,
                        &[(
                            "Location",
                            "https://rp.test/cb?error=invalid_request&gematik_error_text=client_id+ist+ung%C3%BCltig&gematik_timestamp=1713603116&gematik_uuid=c0e2a77c&gematik_code=2012&state=s1",
                        )],
                        Vec::new(),
                    ));
                }
                if self.behaviour == Behaviour::RefuseChallengeWithBody {
                    return Ok(Self::respond(
                        400,
                        &[("content-type", "application/json")],
                        r#"{"error":"invalid_request","gematik_error_text":"redirect_uri ist ungültig","gematik_code":"1020","gematik_timestamp":1,"gematik_uuid":"u"}"#,
                    ));
                }
                let body = json!({
                    "challenge": self.challenge(),
                    "user_consent": {
                        "requested_scopes": {"e-rezept": "Zugriff auf die E-Rezept-Funktionalität.", "openid": "Der Zugriff auf den ID-Token."},
                        "requested_claims": {"organizationName": "Zustimmung zur Verarbeitung der Organisationszugehörigkeit"}
                    }
                });
                Self::respond(
                    200,
                    &[("content-type", "application/json")],
                    body.to_string(),
                )
            }
            (Method::Post, "https://idp.test/sign_response") => {
                let body = String::from_utf8(request.body.clone()).unwrap();
                self.posted.borrow_mut().push(body.clone());
                Self::respond(
                    302,
                    &[(
                        "Location",
                        "https://rp.test/cb?code=CODE.jwe.value&state=s1",
                    )],
                    Vec::new(),
                )
            }
            other => panic!("unexpected request {other:?}"),
        })
    }
}

/// A card's key behind the Konnektor: it answers asynchronously, here after being polled
/// once without an answer, as a SOAP call would leave the flow waiting.
struct AwaitedKey(SoftwareKey<Backend>);

impl jwz::keys::JwsKey for AwaitedKey {
    fn algorithm(&self) -> jwz::jwa::SignatureAlgorithm {
        self.0.algorithm()
    }
}

impl jwz::keys::AsyncSigner for AwaitedKey {
    fn sign_async<'a>(
        &'a self,
        msg: &'a [u8],
    ) -> jwz::crypto::asynchronous::BoxFuture<'a, Result<jwz::keys::Signature, jwz::Error>> {
        let mut waited = false;
        Box::pin(std::future::poll_fn(move |_| {
            if waited {
                std::task::Poll::Ready(self.0.try_sign(msg))
            } else {
                waited = true;
                std::task::Poll::Pending
            }
        }))
    }
}

/// Polls `future` until it is ready; the signers here need no wake-up to make progress.
fn spin<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

/// The flow takes an asynchronous signer, as a card at the Konnektor is, and waits for it.
#[test]
fn an_asynchronous_signer_answers_the_challenge() {
    let idp = FakeIdp::new(Behaviour::default());
    let (key, cert) = card();
    let key = AwaitedKey(key);
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    let done = spin(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test/"),
        &identity,
        AUTH_URL,
        NOW,
        &Unverified,
    ))
    .unwrap();
    assert_eq!(done.redirect.code, "CODE.jwe.value");
    assert_eq!(idp.posted.borrow().len(), 1);
}

#[test]
fn the_flow_yields_the_code_and_posts_a_well_formed_signed_challenge() {
    let idp = FakeIdp::new(Behaviour::default());
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    let done = ready(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test/"),
        &identity,
        AUTH_URL,
        NOW,
        &Unverified,
    ))
    .unwrap();
    assert_eq!(done.redirect.code, "CODE.jwe.value");
    assert_eq!(done.redirect.state.as_deref(), Some("s1"));
    assert_eq!(done.discovery.metadata.issuer, "https://idp.test");
    assert_eq!(done.discovery.kid.as_deref(), Some("puk_disc_sig"));
    assert_eq!(done.challenge_claims["client_id"], "gematikTestPs");
    assert_eq!(done.warnings, vec![Warning::IdpCertificatesUnverified]);

    // What the IDP received: `signed_challenge=<compact JWE>` whose protected header is
    // what A_20699-03 asks for, and whose `exp` is the challenge's.
    let posted = idp.posted.borrow();
    assert_eq!(posted.len(), 1);
    let token = posted[0].strip_prefix("signed_challenge=").unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 5, "compact JWE");
    let header: Value = serde_json::from_slice(&base64_url_decode(parts[0])).unwrap();
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A256GCM");
    assert_eq!(header["cty"], "NJWT");
    assert_eq!(header["exp"], NOW + 180);
    assert_eq!(header["epk"]["crv"], "BP-256");
    assert_eq!(header["kid"], "puk_idp_enc");
}

fn base64_url_decode(text: &str) -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(text).unwrap()
}

/// The nested JWT the card signs is the one the IDP wants: `{"njwt": challenge}` under
/// `alg BP256R1`, `typ JWT`, `cty NJWT`, `x5c`.
#[test]
fn the_signed_challenge_nests_the_challenge_under_the_card_certificate() {
    let idp = FakeIdp::new(Behaviour::default());
    let (key, cert) = card();
    let challenge = challenge::parse(
        &idp.send(&challenge::request(AUTH_URL)).unwrap(),
        &idp.idp_sig.public_jwk(),
        NOW,
    )
    .unwrap();
    assert_eq!(challenge.exp, NOW + 180);
    assert_eq!(challenge.claims["nonce"], "n1");
    assert!(challenge.user_consent["requested_scopes"]["openid"].is_string());

    // The same inner token the engine builds, signed here to look inside it.
    let nested = json!({ "njwt": challenge.token }).to_string();
    let signed = jws::sign(
        nested.as_bytes(),
        HeaderParams::new().typ("JWT").cty("NJWT").x5c(&[&cert]),
        &key,
    )
    .unwrap();
    let header: Value =
        serde_json::from_slice(&base64_url_decode(signed.split('.').next().unwrap())).unwrap();
    assert_eq!(header["alg"], "BP256R1");
    assert_eq!(header["cty"], "NJWT");
    assert_eq!(header["x5c"].as_array().unwrap().len(), 1);

    // An ES256 signer (ePA's) is not what the IDP accepts for the challenge.
    let es256 = jwz_brainpool::BrainpoolEs256Key::generate(backend().as_ref().rng()).unwrap();
    let metadata = discovery::parse(
        &idp.send(&discovery::request(&Idp::new("https://idp.test")))
            .unwrap(),
        NOW,
    )
    .unwrap()
    .metadata;
    let error = ready(challenge::respond(
        &challenge,
        &es256,
        &cert,
        &idp.idp_enc,
        &metadata,
    ))
    .unwrap_err();
    assert!(
        matches!(
            error,
            Error::SignerAlgorithm {
                needed: "BP256R1",
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn the_idps_refusals_are_reported_with_their_gematik_fields() {
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    let idp = FakeIdp::new(Behaviour::RefuseChallengeInRedirect);
    let error = ready(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test"),
        &identity,
        AUTH_URL,
        NOW,
        &Unverified,
    ))
    .unwrap_err();
    let Error::Idp(refusal) = error else {
        panic!("{error}");
    };
    assert_eq!(refusal.error, "invalid_request");
    assert_eq!(
        refusal.gematik_error_text.as_deref(),
        Some("client_id ist ungültig")
    );
    assert_eq!(refusal.gematik_code.as_deref(), Some("2012"));
    assert_eq!(refusal.gematik_timestamp, Some(1_713_603_116));
    assert_eq!(refusal.http_status, None);
    assert_eq!(
        refusal.to_string(),
        "invalid_request: client_id ist ungültig (gematik_code 2012, c0e2a77c)"
    );

    let idp = FakeIdp::new(Behaviour::RefuseChallengeWithBody);
    let error = ready(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test"),
        &identity,
        AUTH_URL,
        NOW,
        &Unverified,
    ))
    .unwrap_err();
    let Error::Idp(refusal) = error else {
        panic!("{error}");
    };
    assert_eq!(refusal.http_status, Some(400));
    assert_eq!(refusal.gematik_code.as_deref(), Some("1020"));
}

#[test]
fn a_challenge_that_does_not_verify_or_has_expired_is_refused() {
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    for (behaviour, what) in [
        (Behaviour::ChallengeSignedByOtherKey, "challenge signature"),
        (Behaviour::ChallengeExpired, "challenge validity"),
    ] {
        let idp = FakeIdp::new(behaviour);
        let error = ready(authenticator::authenticate(
            &idp,
            &Idp::new("https://idp.test"),
            &identity,
            AUTH_URL,
            NOW,
            &Unverified,
        ))
        .unwrap_err();
        assert!(
            matches!(error, Error::Jose { what: w, .. } if w == what),
            "{what}: {error}"
        );
        assert!(
            idp.posted.borrow().is_empty(),
            "nothing is signed for a bad challenge"
        );
    }

    let idp = FakeIdp::new(Behaviour::DiscoveryWithoutX5c);
    let error = discovery::parse(
        &idp.send(&discovery::request(&Idp::new("https://idp.test")))
            .unwrap(),
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "discovery document",
                ..
            }
        ),
        "{error}"
    );
}

/// A trust check that records what it saw and answers with `answer`.
struct Recording {
    answer: Result<Checked, String>,
    seen: RefCell<Vec<(IdpCertificate, Vec<u8>)>>,
}

impl CertificateTrust for Recording {
    fn check(&self, which: IdpCertificate, der: &[u8], _: &[Vec<u8>]) -> Result<Checked, String> {
        self.seen.borrow_mut().push((which, der.to_vec()));
        self.answer.clone()
    }
}

#[test]
fn both_idp_certificates_go_to_the_trust_check_and_verified_ones_leave_no_warning() {
    let idp = FakeIdp::new(Behaviour::default());
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    let trust = Recording {
        answer: Ok(Checked::Verified),
        seen: RefCell::new(Vec::new()),
    };
    let done = ready(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test"),
        &identity,
        AUTH_URL,
        NOW,
        &trust,
    ))
    .unwrap();
    assert!(done.warnings.is_empty());
    let seen = trust.seen.borrow();
    assert_eq!(
        seen.iter().map(|(w, _)| *w).collect::<Vec<_>>(),
        [IdpCertificate::DiscoverySigner, IdpCertificate::TokenSigner]
    );
    assert_eq!(seen[0].1, idp.disc_cert);
    assert_eq!(seen[1].1, idp.idp_sig_cert);
    assert_eq!(done.certificates.len(), 2);
    assert!(
        done.certificates
            .iter()
            .all(|c| c.checked == Checked::Verified)
    );
}

#[test]
fn a_refused_idp_certificate_stops_the_flow_before_the_card_signs() {
    let idp = FakeIdp::new(Behaviour::default());
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    let trust = Recording {
        answer: Err("revoked".into()),
        seen: RefCell::new(Vec::new()),
    };
    let error = ready(authenticator::authenticate(
        &idp,
        &Idp::new("https://idp.test"),
        &identity,
        AUTH_URL,
        NOW,
        &trust,
    ))
    .unwrap_err();
    assert!(
        matches!(&error, Error::Untrusted { which: IdpCertificate::DiscoverySigner, detail } if detail == "revoked"),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "the IDP's puk_disc_sig certificate is not trusted: revoked"
    );
    assert!(idp.posted.borrow().is_empty());
}

#[test]
fn puk_idp_sig_must_come_with_its_own_certificate() {
    let (key, cert) = card();
    let identity = Identity {
        signer: &key,
        certificate_der: &cert,
    };
    for (behaviour, detail) in [
        (Behaviour::IdpSigWithoutX5c, "no x5c"),
        (Behaviour::IdpSigX5cOfOtherKey, "another key"),
    ] {
        let idp = FakeIdp::new(behaviour);
        let error = ready(authenticator::authenticate(
            &idp,
            &Idp::new("https://idp.test"),
            &identity,
            AUTH_URL,
            NOW,
            &Unverified,
        ))
        .unwrap_err();
        assert!(
            matches!(&error, Error::Malformed { what: "PuK_IDP_SIG", detail: d } if d.contains(detail)),
            "{error}"
        );
        assert!(idp.posted.borrow().is_empty());
    }
}

#[test]
fn the_environments_name_gematiks_idps() {
    assert_eq!(
        Idp::for_env(ti_idpd::Env::Prod).base_url(),
        "https://idp.app.ti-dienste.de"
    );
    assert_eq!(
        Idp::for_env(ti_idpd::Env::Ref).base_url(),
        "https://idp-ref.app.ti-dienste.de"
    );
    assert_eq!(
        Idp::for_env(ti_idpd::Env::Dev).base_url(),
        "https://idp-ref.app.ti-dienste.de"
    );
    assert_eq!(
        Idp::for_env(ti_idpd::Env::Test).base_url(),
        "https://idp-test.app.ti-dienste.de"
    );
    let cert = Certificate::from_der(&card().1).unwrap();
    assert!(cert.subject_cn().contains("TEST-ONLY"));
}
