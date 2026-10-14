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

//! The owner authentication's steps against responses as gemSpec_VZD_FHIR_Directory and
//! I_VZD_Owner describe them, and the guards that keep the identity from signing for a
//! foreign IDP or sending the code elsewhere. The IDP-Dienst flow itself is ti-idpd's
//! to test; `login` is tried end to end by ti-cli against loopback fakes.

use std::cell::RefCell;

use base64ct::{Base64UrlUnpadded, Encoding};
use jwz::keys::SoftwareKey;
use serde_json::json;
use ti_directory::TokenClaims;
use ti_directory::http::{Method, Request, Response, Transport, TransportError};
use ti_directory::owner::{self, SIGN_IN_PATH};
use ti_directory::{Directory, Env, Error, Idp};
use ti_idpd::authenticator::Identity;
use ti_idpd::challenge::CodeRedirect;
use ti_idpd::trust::Unverified;

const DIRECTORY: &str = "https://directory.test";
const IDP: &str = "https://idp.test";
const AUTH_URL: &str = "https://idp.test/auth?response_type=code&client_id=opaque&scope=fhir-vzd+openid&redirect_uri=https%3A%2F%2Fdirectory.test%2Fsignin-gematik-idp-dienst&state=s1&code_challenge=c&code_challenge_method=S256";

fn directory() -> Directory {
    Directory::new(DIRECTORY, Idp::new(IDP))
}

fn response(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
    Response {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    }
}

fn jwt(payload: &serde_json::Value) -> String {
    let part = |v: &[u8]| Base64UrlUnpadded::encode_string(v);
    format!(
        "{}.{}.{}",
        part(br#"{"alg":"ES256","typ":"JWT"}"#),
        part(payload.to_string().as_bytes()),
        part(&[7; 64])
    )
}

#[test]
fn the_environments_name_gematiks_directories_and_idps() {
    let prod = Directory::for_env(Env::Prod);
    assert_eq!(prod.base_url(), "https://fhir-directory.vzd.ti-dienste.de");
    assert_eq!(prod.idp().base_url(), "https://idp.app.ti-dienste.de");
    let test = Directory::for_env(Env::Test);
    assert_eq!(
        test.base_url(),
        "https://fhir-directory-tu.vzd.ti-dienste.de"
    );
    assert_eq!(test.idp().base_url(), "https://idp-test.app.ti-dienste.de");
    for env in [Env::Ref, Env::Dev] {
        let d = Directory::for_env(env);
        assert_eq!(d.base_url(), "https://fhir-directory-ref.vzd.ti-dienste.de");
        assert_eq!(d.idp().base_url(), "https://idp-ref.app.ti-dienste.de");
    }
    assert_eq!(
        Directory::new("https://d.test/", Idp::new(IDP)).base_url(),
        "https://d.test"
    );
}

#[test]
fn the_start_is_a_get_of_owner_authenticate_and_its_redirect_is_the_authorization_url() {
    let request = owner::start(&directory());
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.url, "https://directory.test/owner-authenticate");
    assert!(request.body.is_empty());

    let url = owner::authorization_url(&directory(), &response(302, &[("Location", AUTH_URL)], ""))
        .unwrap();
    assert_eq!(url, AUTH_URL);
}

#[test]
fn a_redirect_to_another_idp_is_refused_before_anything_is_signed() {
    let foreign = "https://idp.evil.test/auth?client_id=opaque";
    let error =
        owner::authorization_url(&directory(), &response(302, &[("Location", foreign)], ""))
            .unwrap_err();
    assert!(
        matches!(&error, Error::Malformed { what: "owner-authenticate", detail } if detail.contains("idp.evil.test") && detail.contains(IDP)),
        "{error}"
    );
    // The port and the scheme are part of the origin.
    let d = Directory::new("http://127.0.0.1:8085", Idp::new("http://127.0.0.1:9000"));
    assert!(
        owner::authorization_url(
            &d,
            &response(302, &[("Location", "http://127.0.0.1:9000/auth?x")], "")
        )
        .is_ok()
    );
    assert!(
        owner::authorization_url(
            &d,
            &response(302, &[("Location", "http://127.0.0.1:9001/auth?x")], "")
        )
        .is_err()
    );
    assert!(
        owner::authorization_url(
            &d,
            &response(302, &[("Location", "https://127.0.0.1:9000/auth?x")], "")
        )
        .is_err()
    );

    let error = owner::authorization_url(&directory(), &response(302, &[], "")).unwrap_err();
    assert!(matches!(error, Error::Malformed { .. }), "{error}");
}

#[test]
fn the_directorys_refusals_carry_its_message_and_attributes() {
    let body = r#"{"message":"Owner not found","errors":[{"attributeName":"telematikId","attributeError":"no entry"}]}"#;
    let error = owner::authorization_url(
        &directory(),
        &response(401, &[("content-type", "application/json")], body),
    )
    .unwrap_err();
    let Error::Directory(refusal) = &error else {
        panic!("{error}")
    };
    assert_eq!(refusal.http_status, 401);
    assert_eq!(refusal.message.as_deref(), Some("Owner not found"));
    assert_eq!(refusal.errors.len(), 1);
    assert_eq!(
        error.to_string(),
        "FHIR-Directory refused: HTTP 401 Owner not found; telematikId: no entry"
    );

    let error = owner::token(&response(
        503,
        &[],
        "<html><body>\n  <h1>maintenance</h1>\n  until 6\n</body></html>",
    ))
    .unwrap_err();
    assert!(
        matches!(&error, Error::Status { what: "signin-gematik-idp-dienst", status: 503, body: Some(b) } if b == "maintenance until 6"),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "FHIR-Directory signin-gematik-idp-dienst: HTTP 503: maintenance until 6"
    );
    let error = owner::token(&response(502, &[], "")).unwrap_err();
    assert!(
        matches!(&error, Error::Status { body: None, .. }),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "FHIR-Directory signin-gematik-idp-dienst: HTTP 502"
    );

    // The RU directory's own shape: `errors` is null when there is nothing to list.
    let body = r#"{"errors":null,"message":"Validation Failure: Unknown Telematik ID. Please verify that the provided ID exists in the FHIR Directory.\nTelematik ID: 3-2-X ErrorCode=[b2acbf42]"}"#;
    let error = owner::token(&response(
        403,
        &[("content-type", "application/json")],
        body,
    ))
    .unwrap_err();
    let Error::Directory(refusal) = &error else {
        panic!("{error}")
    };
    assert_eq!(refusal.http_status, 403);
    assert!(refusal.errors.is_empty());
    assert!(
        error.to_string().starts_with(
            "FHIR-Directory refused: HTTP 403 Validation Failure: Unknown Telematik ID"
        ),
        "{error}"
    );
}

#[test]
fn the_sign_in_follows_the_idps_redirect_only_to_the_directory() {
    let redirect = |url: &str| CodeRedirect {
        url: url.to_owned(),
        code: "CODE".to_owned(),
        state: Some("s1".to_owned()),
    };
    let ok = format!("{DIRECTORY}{SIGN_IN_PATH}?code=CODE&state=s1");
    let request = owner::sign_in(&directory(), &redirect(&ok)).unwrap();
    assert_eq!(request.method, Method::Get);
    assert_eq!(request.url, ok);

    for wrong in [
        "https://directory.evil.test/signin-gematik-idp-dienst?code=CODE",
        "https://directory.test/signin-gematik-idp-dienst-decoupled?code=CODE",
        "https://directory.test/owner?code=CODE",
    ] {
        let error = owner::sign_in(&directory(), &redirect(wrong)).unwrap_err();
        assert!(
            matches!(
                error,
                Error::Malformed {
                    what: "code redirect",
                    ..
                }
            ),
            "{wrong}: {error}"
        );
    }
}

#[test]
fn the_token_document_yields_the_token_and_its_claims() {
    let payload = json!({
        "iss": "https://directory.test/owner-authenticate",
        "sub": "1-2-ARZTPRAXIS-TESTONLY01",
        "aud": ["https://directory.test/owner", "https://directory.test/search"],
        "iat": 1_760_000_000u64, "exp": 1_760_086_400u64,
        "scope": "owner:read owner:write search:read",
    });
    let body = json!({"access_token": jwt(&payload), "token_type": "Bearer", "expires_in": 86_400});
    let token = owner::token(&response(
        200,
        &[("content-type", "application/json")],
        &body.to_string(),
    ))
    .unwrap();
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, 86_400);
    assert_eq!(
        token.claims.sub.as_deref(),
        Some("1-2-ARZTPRAXIS-TESTONLY01")
    );
    assert_eq!(token.claims.aud.len(), 2);
    assert_eq!(token.claims.exp, Some(1_760_086_400));
    assert_eq!(
        token.claims.scope.as_deref(),
        Some("owner:read owner:write search:read")
    );

    // A token with other claims is still a token.
    let body =
        json!({"access_token": jwt(&json!({"foo": 1})), "token_type": "Bearer", "expires_in": 1});
    let token = owner::token(&response(200, &[], &body.to_string())).unwrap();
    assert_eq!(token.claims, TokenClaims::default());

    for (body, why) in [
        (
            r#"{"token_type":"Bearer","expires_in":1}"#,
            "no access_token",
        ),
        (
            r#"{"access_token":"","token_type":"Bearer","expires_in":1}"#,
            "empty",
        ),
        (
            r#"{"access_token":"opaque","token_type":"Bearer","expires_in":1}"#,
            "not a JWT",
        ),
        ("not json", "not JSON"),
    ] {
        let error = owner::token(&response(200, &[], body)).unwrap_err();
        assert!(matches!(error, Error::Malformed { .. }), "{why}: {error}");
    }
}

/// A transport that answers the first request and records everything.
struct Scripted {
    first: Response,
    seen: RefCell<Vec<Request>>,
}

impl Transport for Scripted {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        self.seen.borrow_mut().push(request.clone());
        if self.seen.borrow().len() == 1 {
            Ok(self.first.clone())
        } else {
            Err(TransportError(
                "the test expected no further request".into(),
            ))
        }
    }
}

#[test]
fn login_stops_at_the_directorys_redirect_when_it_is_not_the_idps() {
    let key = SoftwareKey::generate(
        jwz_brainpool::BP256R1,
        &jwz_brainpool::registry(),
        std::sync::Arc::new(jwz_brainpool::backend(
            jwz::crypto::rustcrypto::RustCrypto::new(),
        )),
    )
    .unwrap();
    let identity = Identity {
        signer: &key,
        certificate_der: &[0x30, 0x00],
    };
    let transport = Scripted {
        first: response(
            302,
            &[("Location", "https://idp.evil.test/auth?client_id=opaque")],
            "",
        ),
        seen: RefCell::new(Vec::new()),
    };
    let error = owner::login(
        &transport,
        &directory(),
        &identity,
        1_760_000_000,
        &Unverified,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            Error::Malformed {
                what: "owner-authenticate",
                ..
            }
        ),
        "{error}"
    );
    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1, "nothing goes to the foreign IDP");
    assert_eq!(seen[0].url, "https://directory.test/owner-authenticate");

    let transport = Scripted {
        first: response(401, &[], r#"{"message":"nope"}"#),
        seen: RefCell::new(Vec::new()),
    };
    let error = owner::login(
        &transport,
        &directory(),
        &identity,
        1_760_000_000,
        &Unverified,
    )
    .unwrap_err();
    assert!(matches!(error, Error::Directory(_)), "{error}");
}
