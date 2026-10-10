//! `ti directory login` end to end against a FHIR-Directory and an IDP-Dienst on the
//! loopback: the directory's redirect, the Authenticator-Modul flow with the identity
//! from the fixtures, the sign-in with the code, the owner access token.

#[path = "support/loopback.rs"]
mod loopback;
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use base64ct::{Base64UrlUnpadded, Encoding};
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

/// A FHIR-Directory on the loopback with `idp` as its IDP-Dienst.
fn directory(idp: &str, behaviour: Behaviour) -> Server {
    let idp = idp.to_owned();
    Server::start(|own| {
        let own = own.to_owned();
        move |request: &Seen| {
            match (request.method.as_str(), request.path()) {
            ("GET", "/owner-authenticate") => {
                let idp = if behaviour == Behaviour::ForeignIdp {
                    "http://127.0.0.1:1"
                } else {
                    &idp
                };
                let location = format!(
                    "{idp}/sign_response?response_type=code&client_id=GEMopaqueDirectory&scope=fhir-vzd+openid&redirect_uri={}&state=8gdEEbyU2MY&code_challenge=UgY_wxyo&code_challenge_method=S256",
                    percent_encode(&format!("{own}/signin-gematik-idp-dienst"))
                );
                http(302, "text/plain", b"", Some(&location))
            }
            ("GET", "/signin-gematik-idp-dienst")
                if behaviour != Behaviour::Refuse
                    && request.query("code").as_deref() == Some("CODE.from.idp")
                    && request.query("state").as_deref() == Some("8gdEEbyU2MY") =>
            {
                let part = |v: &[u8]| Base64UrlUnpadded::encode_string(v);
                let payload = json!({
                    "iss": format!("{own}/owner-authenticate"),
                    "sub": "1-2-ARZTPRAXIS-TESTONLY01",
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
                let body = json!({"access_token": token, "token_type": "Bearer", "expires_in": 86_400});
                http(200, "application/json", body.to_string().as_bytes(), None)
            }
            ("GET", "/signin-gematik-idp-dienst") => http(
                401,
                "application/json",
                br#"{"message":"Authentication failed","errors":[{"attributeName":"code","attributeError":"unknown"}]}"#,
                None,
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

fn login(directory: &Server, idp: &FakeIdp, identity: &[&str]) -> Output {
    let mut args = vec![
        "directory",
        "login",
        "--url",
        &directory.base_url,
        "--idp-url",
        &idp.base_url,
    ];
    args.extend_from_slice(identity);
    ti(&args)
}

#[test]
fn login_yields_the_owner_access_token() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::Normal);
    let out = login(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("directory login", &out.stdout);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["token_type"], "Bearer");
    assert_eq!(report["expires_in"], 86_400);
    let expires_at = report["expires_at"].as_u64().unwrap();
    assert!((now() + 86_000..=now() + 86_400).contains(&expires_at));
    assert_eq!(report["token"]["sub"], "1-2-ARZTPRAXIS-TESTONLY01");
    assert_eq!(
        report["token"]["scope"],
        "owner:read owner:write search:read"
    );
    assert_eq!(report["token"]["aud"].as_array().unwrap().len(), 2);
    assert_eq!(report["directory"]["base_url"], dir.base_url);
    assert!(
        report["directory"]["authorization_url"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}/sign_response?", idp.base_url))
    );
    assert_eq!(report["idp"]["issuer"], idp.base_url);
    assert_eq!(
        report["identity"]["telematik_id"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    assert_eq!(report["challenge"]["client_id"], "GEMopaqueDirectory");
    assert_eq!(report["challenge"]["scope"], "fhir-vzd openid");
    assert_eq!(report["warnings"], json!(["idp_certificates_unverified"]));
    let token = report["access_token"].as_str().unwrap();
    assert_eq!(token.split('.').count(), 3);

    // The IDP got one signed challenge; the directory got the start and the sign-in
    // with the code the IDP issued and the state it was given.
    assert_eq!(idp.stop().len(), 1);
    let seen = dir.stop();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path(), "/owner-authenticate");
    assert_eq!(seen[1].path(), "/signin-gematik-idp-dienst");
    assert_eq!(seen[1].query("code").as_deref(), Some("CODE.from.idp"));
    assert_eq!(seen[1].query("state").as_deref(), Some("8gdEEbyU2MY"));
}

#[test]
fn a_redirect_to_a_foreign_idp_stops_the_login_before_the_card_signs() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::ForeignIdp);
    let out = login(
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
    assert_conforms("error", &out.stderr);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "directory_protocol");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("127.0.0.1:1"), "{message}");
    assert!(idp.stop().is_empty(), "nothing reached the IDP");
    assert_eq!(dir.stop().len(), 1);
}

#[test]
fn the_directorys_refusal_is_a_directory_error_with_its_message() {
    let idp = FakeIdp::start(Answer::Code);
    let dir = directory(&idp.base_url, Behaviour::Refuse);
    let out = login(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]);
    assert_eq!(out.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "directory_error");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("HTTP 401"), "{message}");
    assert!(message.contains("Authentication failed"), "{message}");
    assert!(message.contains("code: unknown"), "{message}");
}

#[test]
fn the_idps_refusal_stays_an_idpd_error() {
    let idp = FakeIdp::start(Answer::Refuse);
    let dir = directory(&idp.base_url, Behaviour::Normal);
    let out = login(&dir, &idp, &["--p12", &identity_fixture("aut.p12")]);
    assert_eq!(out.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "idpd_error");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Karte unbekannt")
    );
    // The code never existed, so the directory saw only the start.
    assert_eq!(dir.stop().len(), 1);
}

#[test]
fn the_environment_or_both_urls_are_required() {
    let p12 = identity_fixture("aut.p12");
    let out = ti(&["directory", "login", "--p12", &p12]);
    assert_eq!(out.status.code(), Some(2), "no environment and no URL");
    let out = ti(&[
        "directory",
        "login",
        "--url",
        "https://directory.test",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "--url without --idp-url");
    let out = ti(&[
        "directory",
        "login",
        "--env",
        "ref",
        "--idp-url",
        "https://idp.test",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "--idp-url needs --url");
    let out = ti(&["directory", "login", "--env", "auto", "--p12", &p12]);
    assert_eq!(out.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "environment_invalid");
}
