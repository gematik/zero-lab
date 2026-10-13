/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
 */

//! `ti directory login …` end to end against a FHIR-Directory, its Keycloak and an
//! IDP-Dienst on the loopback: owner by card, owner with a RegService-OpenID-Token, and
//! holder, service and ti-provider with client credentials.

#[path = "support/loopback.rs"]
mod loopback;
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use loopback::{Answer, FakeIdp, Seen, Server, http, now, percent_encode};
use serde_json::{Value, json};
use support::assert_conforms;

/// How the fake directory deviates from a well-behaved one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    Normal,
    /// Redirects to an IDP that is not the one the client was told.
    ForeignIdp,
    /// Refuses the sign-in.
    Refuse,
}

const STATE: &str = "8gdEEbyU2MY";
const REGSERVICE_TOKEN: &str = "REG.SERVICE.TOKEN";
const KEYCLOAK_TOKEN: &str = "KEYCLOAK.TOKEN";

/// A directory token as the directory issues it, `iss` its endpoint.
fn directory_token(own: &str, endpoint: &str, sub: &str) -> Vec<u8> {
    let part = |v: &[u8]| Base64UrlUnpadded::encode_string(v);
    let payload = json!({
        "iss": format!("{own}/{endpoint}-authenticate"),
        "sub": sub,
        "aud": [format!("{own}/owner"), format!("{own}/search")],
        "iat": now(), "exp": now() + 86_400,
        "scope": "owner:read owner:write search:read",
    });
    let token = format!(
        "{}.{}.{}",
        part(br#"{"alg":"ES256","typ":"JWT"}"#),
        part(payload.to_string().as_bytes()),
        part(&[7; 64])
    );
    json!({"access_token": token, "token_type": "Bearer", "expires_in": 86_400})
        .to_string()
        .into_bytes()
}

fn json_response(status: u16, body: &Value) -> Vec<u8> {
    http(
        status,
        "application/json",
        body.to_string().as_bytes(),
        None,
    )
}

/// The directory's IDP authorization URL for `own`, returning to `sign_in`.
fn authorization_url(idp: &str, own: &str, sign_in: &str) -> String {
    format!(
        "{idp}/sign_response?response_type=code&client_id=GEMopaqueDirectory&scope=fhir-vzd+openid&redirect_uri={}&state={STATE}&code_challenge=UgY_wxyo&code_challenge_method=S256",
        percent_encode(&format!("{own}/{sign_in}"))
    )
}

/// A FHIR-Directory on the loopback with `idp` as its IDP-Dienst.
fn directory(idp: &str, behaviour: Behaviour) -> Server {
    let idp = idp.to_owned();
    Server::start(|own| {
        let own = own.to_owned();
        move |request: &Seen| {
            let bearer = request
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "));
            if let Some(bearer) = bearer {
                return exchange(&own, request.path(), bearer);
            }
            card(&own, &idp, behaviour, request).unwrap_or_else(|| {
                let other = (request.method.as_str(), request.path());
                http(404, "text/plain", format!("{other:?}").as_bytes(), None)
            })
        }
    })
}

/// The bearer exchanges: a RegService token at owner, Keycloak's at the others.
fn exchange(own: &str, path: &str, bearer: &str) -> Vec<u8> {
    let accepted = match path {
        "/owner-authenticate" => bearer == REGSERVICE_TOKEN,
        "/holder-authenticate" | "/service-authenticate" | "/ti-provider-authenticate" => {
            bearer == KEYCLOAK_TOKEN
        }
        _ => return http(404, "text/plain", path.as_bytes(), None),
    };
    if !accepted {
        return json_response(
            403,
            &json!({"errors": null, "message": "Access Token unknown or expired"}),
        );
    }
    let endpoint = path
        .trim_start_matches('/')
        .trim_end_matches("-authenticate");
    let sub = if endpoint == "owner" {
        "1-2-REGSERVICE"
    } else {
        "client-1"
    };
    http(
        200,
        "application/json",
        &directory_token(own, endpoint, sub),
        None,
    )
}

/// The owner login by card: the redirect to the IDP and the sign-in.
fn card(own: &str, idp: &str, behaviour: Behaviour, request: &Seen) -> Option<Vec<u8>> {
    Some(match (request.method.as_str(), request.path()) {
        ("GET", "/owner-authenticate") => {
            let idp = if behaviour == Behaviour::ForeignIdp {
                "http://127.0.0.1:1"
            } else {
                idp
            };
            let location = authorization_url(idp, own, "signin-gematik-idp-dienst");
            http(302, "text/plain", b"", Some(&location))
        }
        ("GET", "/signin-gematik-idp-dienst")
            if behaviour != Behaviour::Refuse
                && request.query("code").as_deref() == Some("CODE.from.idp")
                && request.query("state").as_deref() == Some(STATE) =>
        {
            let token = directory_token(own, "owner", "1-2-ARZTPRAXIS-TESTONLY01");
            http(200, "application/json", &token, None)
        }
        ("GET", "/signin-gematik-idp-dienst") => json_response(
            401,
            &json!({"message": "Authentication failed", "errors": [{"attributeName": "code", "attributeError": "unknown"}]}),
        ),
        _ => return None,
    })
}

/// A Keycloak on the loopback: client credentials `client-1`/`s3cret` in any realm.
fn keycloak() -> Server {
    Server::start(|_| {
        move |request: &Seen| {
            let realm_path = request
                .path()
                .strip_prefix("/auth/realms/")
                .unwrap_or_default();
            let basic = request
                .header("authorization")
                .and_then(|v| v.strip_prefix("Basic "))
                .and_then(|b| Base64::decode_vec(b).ok());
            match (
                request.method.as_str(),
                realm_path.ends_with("/protocol/openid-connect/token"),
            ) {
                ("POST", true)
                    if request.body == "grant_type=client_credentials"
                        && basic.as_deref() == Some(b"client-1:s3cret".as_slice()) =>
                {
                    json_response(
                        200,
                        &json!({"access_token": KEYCLOAK_TOKEN, "expires_in": 300, "token_type": "Bearer"}),
                    )
                }
                ("POST", true) => json_response(
                    401,
                    &json!({"error": "unauthorized_client", "error_description": "Invalid client or Invalid client credentials"}),
                ),
                other => http(404, "text/plain", format!("{other:?}").as_bytes(), None),
            }
        }
    })
}

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn identity_fixture(name: &str) -> String {
    manifest("tests/fixtures/identity")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn ti(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ti"))
        .args(["--format", "json"])
        .args(args)
        .env_remove("TI_FORMAT")
        .env_remove("TI_ENV")
        .env_remove("TI_P12_PASSWORD_PATH")
        .env_remove("TI_DIRECTORY_CLIENT_ID")
        .env_remove("TI_DIRECTORY_CLIENT_SECRET_PATH")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY")
        .env(
            "TI_CACHE_DIR",
            std::env::temp_dir().join("ti-tests-no-cache"),
        )
        .output()
        .unwrap()
}

fn ok(out: &Output) -> Value {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("directory login", &out.stdout);
    serde_json::from_slice(&out.stdout).unwrap()
}

fn error_kind(out: &Output) -> String {
    assert_conforms("error", &out.stderr);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    error["error"]["kind"].as_str().unwrap().to_owned()
}

fn owner(directory: &Server, idp: &FakeIdp, extra: &[&str]) -> Output {
    let mut args = vec![
        "directory",
        "login",
        "owner",
        "--url",
        &directory.base_url,
        "--idp-url",
        &idp.base_url,
        "--idp-unverified",
    ];
    args.extend_from_slice(extra);
    ti(&args)
}

fn file(name: &str, content: &str) -> String {
    let path = std::env::temp_dir().join(format!("ti-directory-{}-{name}", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn owner_by_card_yields_the_owner_token() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::Normal);
    let report = ok(&owner(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]));
    assert_eq!(
        (report["endpoint"].as_str(), report["method"].as_str()),
        (Some("owner"), Some("card"))
    );
    assert_eq!(report["token"]["sub"], "1-2-ARZTPRAXIS-TESTONLY01");
    let expires_at = report["expires_at"].as_u64().unwrap();
    assert!((now() + 86_000..=now() + 86_400).contains(&expires_at));
    assert_eq!(
        report["directory"]["endpoint_url"],
        format!("{}/owner-authenticate", dir.base_url)
    );
    assert!(
        report["directory"]["authorization_url"]
            .as_str()
            .unwrap()
            .starts_with(&idp.base_url)
    );
    assert_eq!(
        report["identity"]["telematik_id"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    assert_eq!(report["challenge"]["client_id"], "GEMopaqueDirectory");
    assert_eq!(report["client_id"], Value::Null);
    assert_eq!(report["warnings"], json!(["idp_certificates_unverified"]));

    assert_eq!(idp.stop().len(), 1);
    let seen = dir.stop();
    assert_eq!(
        seen.iter().map(Seen::path).collect::<Vec<_>>(),
        ["/owner-authenticate", "/signin-gematik-idp-dienst"]
    );
}

#[test]
fn token_prints_only_the_bearer() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::Normal);
    let out = owner(
        &dir,
        &idp,
        &["--p12", &identity_fixture("aut.p12"), "--token"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.trim_end().split('.').count(), 3, "{text}");
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn owner_with_a_regservice_token_exchanges_it() {
    let dir = directory("http://127.0.0.1:1", Behaviour::Normal);
    let token = file("reg.jwt", &format!("{REGSERVICE_TOKEN}\n"));
    let report = ok(&ti(&[
        "directory",
        "login",
        "owner",
        "--url",
        &dir.base_url,
        "--regservice-token-path",
        &token,
    ]));
    assert_eq!(
        (report["method"].as_str(), report["token"]["sub"].as_str()),
        (Some("regservice"), Some("1-2-REGSERVICE"))
    );
    assert_eq!(report["identity"], Value::Null);

    let wrong = file("wrong.jwt", "OTHER.TOKEN");
    let out = ti(&[
        "directory",
        "login",
        "owner",
        "--url",
        &dir.base_url,
        "--regservice-token-path",
        &wrong,
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(error_kind(&out), "directory_error");
}

#[test]
fn client_credentials_for_holder_service_and_ti_provider() {
    let dir = directory("http://127.0.0.1:1", Behaviour::Normal);
    let kc = keycloak();
    let secret = file("secret.txt", "s3cret\n");
    for endpoint in ["holder", "service", "ti-provider"] {
        let report = ok(&ti(&[
            "directory",
            "login",
            endpoint,
            "--url",
            &dir.base_url,
            "--auth-url",
            &kc.base_url,
            "--client-id",
            "client-1",
            "--client-secret-path",
            &secret,
        ]));
        assert_eq!(report["endpoint"], endpoint);
        assert_eq!(report["method"], "client_credentials");
        assert_eq!(report["client_id"], "client-1");
        assert_eq!(
            report["token"]["iss"],
            format!("{}/{endpoint}-authenticate", dir.base_url)
        );
    }
    let realms: Vec<String> = kc
        .stop()
        .iter()
        .map(|s| s.path().split('/').nth(3).unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        realms,
        [
            "RSDirectoryAdministration",
            "Service-Authenticate",
            "TI-Provider"
        ]
    );

    let kc = keycloak();
    let wrong = file("wrong.txt", "nope");
    let out = ti(&[
        "directory",
        "login",
        "service",
        "--url",
        &dir.base_url,
        "--auth-url",
        &kc.base_url,
        "--client-id",
        "client-1",
        "--client-secret-path",
        &wrong,
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(error_kind(&out), "directory_auth_server_error");
}

#[test]
fn a_redirect_to_a_foreign_idp_stops_the_login_before_the_card_signs() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::ForeignIdp);
    let out = owner(
        &dir,
        &idp,
        &[
            "--cert",
            &identity_fixture("aut-chain.pem"),
            "--key",
            &identity_fixture("aut.key"),
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(error_kind(&out), "directory_protocol");
    assert!(idp.stop().is_empty(), "nothing reached the IDP");
}

#[test]
fn refusals_keep_their_kinds() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::Refuse);
    let out = owner(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]);
    assert_eq!(
        (out.status.code(), error_kind(&out).as_str()),
        (Some(3), "directory_error")
    );

    let idp = FakeIdp::start(Answer::Refuse);
    let dir = directory(&idp.base_url, Behaviour::Normal);
    let out = owner(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]);
    assert_eq!(
        (out.status.code(), error_kind(&out).as_str()),
        (Some(3), "idpd_error")
    );
}

#[test]
fn arguments_are_checked_before_anything_is_sent() {
    let p12 = identity_fixture("aut.p12");
    let secret = file("args-secret.txt", "x");
    for (args, kind) in [
        (
            vec!["directory", "login", "owner", "--env", "ref"],
            Some("arguments_invalid"),
        ),
        (
            vec![
                "directory",
                "login",
                "owner",
                "--url",
                "https://d.test",
                "--p12",
                &p12,
            ],
            Some("arguments_invalid"),
        ),
        (
            vec![
                "directory",
                "login",
                "service",
                "--url",
                "https://d.test",
                "--client-id",
                "c",
                "--client-secret-path",
                &secret,
            ],
            Some("arguments_invalid"),
        ),
        (
            vec![
                "directory",
                "login",
                "owner",
                "--env",
                "auto",
                "--p12",
                &p12,
            ],
            Some("environment_invalid"),
        ),
        (vec!["directory", "login", "owner", "--p12", &p12], None),
        (
            vec![
                "directory",
                "login",
                "service",
                "--env",
                "ref",
                "--client-id",
                "c",
            ],
            None,
        ),
        (
            vec![
                "directory",
                "login",
                "owner",
                "--env",
                "ref",
                "--p12",
                &p12,
                "--regservice-token-path",
                &secret,
            ],
            None,
        ),
    ] {
        let out = ti(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        if let Some(kind) = kind {
            assert_eq!(error_kind(&out), kind, "{args:?}");
        }
    }
}
