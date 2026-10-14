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

//! The token paths besides the owner login by card: client credentials at Keycloak
//! exchanged at the directory and a bearer exchanged at `/owner-authenticate`, against
//! responses shaped as gemSpec_VZD_FHIR_Directory, I_VZD_Owner and Keycloak give them
//! (checked on RU, 2026-10-11).

use std::cell::RefCell;
use std::collections::VecDeque;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use serde_json::json;
use ti_directory::http::{Method, Request, Response, Transport, TransportError};
use ti_directory::{Directory, Endpoint, Env, Error, Idp, exchange, keycloak};

const DIRECTORY: &str = "https://directory.test";
const AUTH: &str = "https://auth.test:9443";
const IDP: &str = "https://idp.test";

fn directory() -> Directory {
    Directory::new(DIRECTORY, Idp::new(IDP)).with_auth_url(AUTH)
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.as_bytes().to_vec(),
    }
}

fn directory_token(iss: &str, sub: &str) -> String {
    let part = |v: &[u8]| Base64UrlUnpadded::encode_string(v);
    let jwt = format!(
        "{}.{}.{}",
        part(br#"{"alg":"ES256","typ":"JWT"}"#),
        part(
            json!({"iss": iss, "sub": sub, "scope": "search:read"})
                .to_string()
                .as_bytes()
        ),
        part(&[7; 64])
    );
    json!({"access_token": jwt, "token_type": "bearer", "expires_in": 86_400}).to_string()
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Answers in order and records what it was asked.
struct Scripted {
    answers: RefCell<VecDeque<Response>>,
    seen: RefCell<Vec<Request>>,
}

impl Scripted {
    fn new(answers: Vec<Response>) -> Scripted {
        Scripted {
            answers: RefCell::new(answers.into()),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Transport for Scripted {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        self.seen.borrow_mut().push(request.clone());
        self.answers
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| TransportError("no answer scripted".into()))
    }
}

#[test]
fn endpoints_name_their_paths_and_realms() {
    let rows = [
        (Endpoint::Owner, "owner", "/owner-authenticate", None),
        (
            Endpoint::Holder,
            "holder",
            "/holder-authenticate",
            Some("RSDirectoryAdministration"),
        ),
        (
            Endpoint::Service,
            "service",
            "/service-authenticate",
            Some("Service-Authenticate"),
        ),
        (
            Endpoint::TiProvider,
            "ti-provider",
            "/ti-provider-authenticate",
            Some("TI-Provider"),
        ),
    ];
    for (endpoint, name, path, realm) in rows {
        assert_eq!(
            (endpoint.as_str(), endpoint.path(), endpoint.realm()),
            (name, path, realm)
        );
    }
    let tu = Directory::for_env(Env::Test);
    assert_eq!(tu.base_url(), "https://fhir-directory-tu.vzd.ti-dienste.de");
    assert_eq!(
        tu.auth_url(),
        Some("https://auth-test.vzd.ti-dienste.de:9443")
    );
    assert_eq!(
        Directory::for_env(Env::Ref).auth_url(),
        Some("https://auth-ref.vzd.ti-dienste.de:9443")
    );
    assert_eq!(
        Directory::for_env(Env::Prod).auth_url(),
        Some("https://auth.vzd.ti-dienste.de:9443")
    );
    assert_eq!(Directory::new(DIRECTORY, Idp::new(IDP)).auth_url(), None);
}

#[test]
fn the_keycloak_request_is_client_credentials_with_basic_auth() {
    let request =
        keycloak::token_request(&directory(), Endpoint::Holder, "rs-1", "s3cret").unwrap();
    assert_eq!(request.method, Method::Post);
    assert_eq!(
        request.url,
        "https://auth.test:9443/auth/realms/RSDirectoryAdministration/protocol/openid-connect/token"
    );
    assert_eq!(request.body, b"grant_type=client_credentials");
    let basic = header(&request, "authorization")
        .unwrap()
        .strip_prefix("Basic ")
        .unwrap();
    assert_eq!(Base64::decode_vec(basic).unwrap(), b"rs-1:s3cret");

    let no_auth = Directory::new(DIRECTORY, Idp::new(IDP));
    let error = keycloak::token_request(&no_auth, Endpoint::Service, "a", "b").unwrap_err();
    assert!(matches!(error, Error::NoAuthUrl("service")), "{error}");
    let error = keycloak::token_request(&directory(), Endpoint::Owner, "a", "b").unwrap_err();
    assert!(matches!(error, Error::Malformed { .. }), "{error}");
}

#[test]
fn keycloak_refusals_are_auth_server_errors() {
    let error = keycloak::token(&response(
        401,
        r#"{"error":"unauthorized_client","error_description":"Invalid client or Invalid client credentials"}"#,
    ))
    .unwrap_err();
    let Error::AuthServer(refusal) = &error else {
        panic!("{error}")
    };
    assert_eq!(refusal.http_status, 401);
    assert_eq!(refusal.error, "unauthorized_client");
    assert_eq!(
        error.to_string(),
        "FHIR-Directory Keycloak refused: HTTP 401 unauthorized_client: Invalid client or Invalid client credentials"
    );
    let error = keycloak::token(&response(502, "<html>bad gateway</html>")).unwrap_err();
    assert!(
        matches!(error, Error::Status { status: 502, .. }),
        "{error}"
    );
}

#[test]
fn client_credentials_exchange_the_keycloak_token_at_the_endpoint() {
    let transport = Scripted::new(vec![
        response(
            200,
            r#"{"access_token":"KC.TOKEN","expires_in":300,"token_type":"Bearer"}"#,
        ),
        response(
            200,
            &directory_token("https://directory.test/service-authenticate", "fdv-1"),
        ),
    ]);
    let token = exchange::login_client_credentials(
        &transport,
        &directory(),
        Endpoint::Service,
        "fdv-1",
        "s",
    )
    .unwrap();
    assert_eq!(token.claims.sub.as_deref(), Some("fdv-1"));
    assert_eq!(
        token.claims.iss.as_deref(),
        Some("https://directory.test/service-authenticate")
    );
    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(
        seen[0]
            .url
            .ends_with("/realms/Service-Authenticate/protocol/openid-connect/token")
    );
    assert_eq!(seen[1].method, Method::Get);
    assert_eq!(seen[1].url, "https://directory.test/service-authenticate");
    assert_eq!(header(&seen[1], "authorization"), Some("Bearer KC.TOKEN"));

    // Keycloak refuses: the directory is never asked.
    let transport = Scripted::new(vec![response(401, r#"{"error":"invalid_client"}"#)]);
    let error =
        exchange::login_client_credentials(&transport, &directory(), Endpoint::Holder, "x", "y")
            .unwrap_err();
    assert!(matches!(error, Error::AuthServer(_)), "{error}");
    assert_eq!(transport.seen.borrow().len(), 1);
}

#[test]
fn a_regservice_token_is_a_bearer_at_owner_authenticate() {
    let transport = Scripted::new(vec![response(
        200,
        &directory_token(
            "https://directory.test/owner-authenticate",
            "1-2-ARZTPRAXIS-X",
        ),
    )]);
    let token =
        exchange::login_bearer(&transport, &directory(), Endpoint::Owner, "REG.SERVICE.JWT")
            .unwrap();
    assert_eq!(token.claims.sub.as_deref(), Some("1-2-ARZTPRAXIS-X"));
    let seen = transport.seen.borrow();
    assert_eq!(seen[0].url, "https://directory.test/owner-authenticate");
    assert_eq!(
        header(&seen[0], "authorization"),
        Some("Bearer REG.SERVICE.JWT")
    );

    // The RU directory's answer to a token it does not accept.
    let transport = Scripted::new(vec![response(
        400,
        r#"{"errors":null,"message":"Authorization token missing. ErrorCode=[7589180c]"}"#,
    )]);
    let error = exchange::login_bearer(&transport, &directory(), Endpoint::Holder, "").unwrap_err();
    assert!(matches!(error, Error::Directory(_)), "{error}");
}
