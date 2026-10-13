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

//! `ti idpd authenticate` end to end against an IDP-Dienst on the loopback that signs
//! with ti-idpd's TEST-ONLY signer: the binary, its ureq transport, the identity from
//! the fixtures, and the IDP's answers as gemSpec_IDP_Dienst describes them.

#[path = "support/loopback.rs"]
mod loopback;
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

use base64ct::{Base64UrlUnpadded, Encoding};
use loopback::{Answer, FakeIdp};
use serde_json::{Value, json};
use support::assert_conforms;

fn manifest(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
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

fn identity_fixture(name: &str) -> String {
    manifest("tests/fixtures/identity")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

#[test]
fn authenticate_turns_an_authorization_url_into_a_code() {
    let idp = FakeIdp::start(Answer::Code);
    let auth_url = format!(
        "{}/sign_response?client_id=gematikTestPs&response_type=code&state=s1",
        idp.base_url
    );
    let out = ti(&[
        "idpd",
        "authenticate",
        "--idp-url",
        &idp.base_url,
        "--idp-unverified",
        "--auth-url",
        &auth_url,
        "--p12",
        &identity_fixture("aut.p12"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_conforms("idpd authenticate", &out.stdout);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["code"], "CODE.from.idp");
    assert_eq!(report["state"], "s1");
    assert_eq!(report["idp"]["issuer"], idp.base_url);
    assert_eq!(
        report["identity"]["telematik_id"],
        "1-2-ARZTPRAXIS-TESTONLY01"
    );
    assert_eq!(report["challenge"]["client_id"], "gematikTestPs");
    assert_eq!(report["warnings"], json!(["idp_certificates_unverified"]));
    let certificates = report["idp"]["certificates"].as_array().unwrap();
    assert_eq!(certificates.len(), 2);
    assert_eq!(certificates[0]["key"], "puk_disc_sig");
    assert_eq!(certificates[1]["key"], "puk_idp_sig");
    assert!(certificates.iter().all(|c| c["verified"] == false));

    // The IDP received one signed challenge: a JWE for PuK_IDP_ENC with the profile's
    // header.
    let posted = idp.stop();
    assert_eq!(posted.len(), 1);
    let token = posted[0].strip_prefix("signed_challenge=").unwrap();
    let header: Value = serde_json::from_slice(
        &Base64UrlUnpadded::decode_vec(token.split('.').next().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A256GCM");
    assert_eq!(header["cty"], "NJWT");
    assert_eq!(header["kid"], "puk_idp_enc");
    assert_eq!(header["epk"]["crv"], "BP-256");
}

#[test]
fn the_idps_refusal_is_an_idpd_error_with_its_text() {
    let idp = FakeIdp::start(Answer::Refuse);
    let auth_url = format!("{}/sign_response?client_id=x", idp.base_url);
    let out = ti(&[
        "idpd",
        "authenticate",
        "--idp-url",
        &idp.base_url,
        "--idp-unverified",
        "--auth-url",
        &auth_url,
        "--cert",
        &identity_fixture("aut-chain.pem"),
        "--key",
        &identity_fixture("aut.key"),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_conforms("error", &out.stderr);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "idpd_error");
    let message = error["error"]["message"].as_str().unwrap();
    assert!(message.contains("access_denied"), "{message}");
    assert!(message.contains("Karte unbekannt"), "{message}");
    assert!(message.contains("2030"), "{message}");
}

#[test]
fn the_urls_and_the_environment_are_checked_before_anything_is_sent() {
    let p12 = identity_fixture("aut.p12");
    let out = ti(&[
        "idpd",
        "authenticate",
        "--env",
        "ref",
        "--auth-url",
        "ftp://idp/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "not https");

    let out = ti(&[
        "idpd",
        "authenticate",
        "--auth-url",
        "https://idp.test/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(out.status.code(), Some(2), "no environment and no IDP URL");

    let out = ti(&[
        "idpd",
        "authenticate",
        "--env",
        "auto",
        "--auth-url",
        "https://idp.test/sign_response",
        "--p12",
        &p12,
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "auto has nothing to detect from"
    );
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(error["error"]["kind"], "environment_invalid");
}

/// `identity sign --alg BP256R1`: the IDP's name for the same ECDSA, on the same key.
#[test]
fn identity_sign_takes_the_idp_algorithm_name() {
    let claims = std::env::temp_dir().join(format!("ti-idpd-claims-{}.json", std::process::id()));
    std::fs::write(&claims, br#"{"njwt": "x"}"#).unwrap();
    let out = ti(&[
        "identity",
        "sign",
        "--p12",
        &identity_fixture("aut.p12"),
        "--claims",
        &claims.to_string_lossy(),
        "--alg",
        "BP256R1",
        "--typ",
        "JWT",
        "--header",
        "cty=NJWT",
    ]);
    let _ = std::fs::remove_file(&claims);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["alg"], "BP256R1");
    assert_eq!(report["header"]["alg"], "BP256R1");
    assert_eq!(report["header"]["cty"], "NJWT");
}
