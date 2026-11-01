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

//! Writing `.kon` files (`edit`): addresses as users type them, new files, `set`, new
//! credentials and pins, and the rules for the production environment.

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use ti_connector_client::edit::{
    self, NewConfig, NewCredentials, normalize_address, refusals, with_credentials, with_pin,
};
use ti_connector_client::{Credentials, Dotkon};

const SERVER: &[u8] = include_bytes!("tls/server.pem");
const OTHER: &[u8] = include_bytes!("tls/other.pem");
const CA: &[u8] = include_bytes!("tls/ca.pem");

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}

fn parse(json: &[u8]) -> Dotkon {
    Dotkon::parse_with(json, |_| None).unwrap()
}

fn config() -> NewConfig {
    NewConfig {
        url: "https://konnektor.test:8443".into(),
        env: Some("ru".into()),
        mandant_id: "M1".into(),
        client_system_id: "C1".into(),
        workplace_id: "W1".into(),
        user_id: None,
        credentials: NewCredentials::Basic {
            username: "praxis".into(),
            password: "pw".into(),
        },
        trust_store: vec![der(SERVER)],
        insecure_skip_verify: false,
        expected_host: None,
        rewrite_service_endpoints: false,
    }
}

#[test]
fn every_address_form_becomes_a_url() {
    for (input, url) in [
        (
            "https://kon.example:8443/connector.sds",
            "https://kon.example:8443",
        ),
        ("kon.example", "https://kon.example"),
        ("kon.example:8443", "https://kon.example:8443"),
        ("10.0.0.1", "https://10.0.0.1"),
        ("10.0.0.1:443/x", "https://10.0.0.1:443"),
        ("[fe80::1]", "https://[fe80::1]"),
        ("[fe80::1]:8443", "https://[fe80::1]:8443"),
        ("fe80::1", "https://[fe80::1]"),
        ("  HTTPS://kon.example  ", "https://kon.example"),
    ] {
        assert_eq!(normalize_address(input).as_deref(), Ok(url), "{input}");
    }
}

#[test]
fn addresses_that_cannot_be_a_url_are_refused() {
    for (input, reason) in [
        ("ftp://kon.example", "scheme"),
        ("http://kon.example", "https"),
        ("", "host is missing"),
        (":8443", "host is missing"),
        ("kon.example:0", "port"),
        ("kon.example:99999", "port"),
        ("kon.example:x", "port"),
        ("[fe80::1", "closing ]"),
        ("[fe80::1]8443", ":PORT"),
        ("user@kon.example", "user information"),
    ] {
        let error = normalize_address(input).unwrap_err();
        assert!(error.reason.contains(reason), "{input}: {error}");
    }
}

/// A new file parses back to what it was made from.
#[test]
fn a_new_file_parses_to_its_parts() {
    let json = config().to_json();
    let kon = parse(&json);
    assert_eq!(kon.url, "https://konnektor.test:8443");
    assert_eq!(
        (&*kon.mandant_id, &*kon.client_system_id, &*kon.workplace_id),
        ("M1", "C1", "W1")
    );
    assert_eq!(kon.trust_store, [der(SERVER)]);
    assert!(!kon.insecure_skip_verify);
    let text = String::from_utf8(json).unwrap();
    assert!(text.starts_with("{\n  \"url\""), "{text}");
    assert!(!text.contains("insecureSkipVerify"), "{text}");
    let none = NewConfig {
        credentials: NewCredentials::None,
        ..config()
    };
    assert_eq!(parse(&none.to_json()).credentials, Credentials::None);
}

/// A change must not bring an http url into any file, nor insecureSkipVerify or
/// credentials of type none into a file for the production environment; what the file
/// already has stays the user's to fix.
#[test]
fn a_change_may_not_bring_http_nor_insecure_or_none_into_production() {
    let pu = NewConfig {
        env: Some("pu".into()),
        ..config()
    };
    assert_eq!(refusals(None, &parse(&pu.to_json())), Vec::<String>::new());
    for (change, what) in [
        (
            NewConfig {
                url: "http://konnektor.test".into(),
                ..pu.clone()
            },
            "http",
        ),
        (
            NewConfig {
                insecure_skip_verify: true,
                ..pu.clone()
            },
            "insecureSkipVerify",
        ),
        (
            NewConfig {
                credentials: NewCredentials::None,
                ..pu.clone()
            },
            "none",
        ),
    ] {
        let after = parse(&change.to_json());
        let refused = refusals(None, &after);
        assert_eq!(refused.len(), 1, "{what}: {refused:?}");
        assert!(refused[0].contains(what), "{refused:?}");
        assert!(
            refusals(Some(&after), &after).is_empty(),
            "{what} was there before"
        );
    }
    let ru = NewConfig {
        insecure_skip_verify: true,
        credentials: NewCredentials::None,
        ..config()
    };
    assert_eq!(refusals(None, &parse(&ru.to_json())), Vec::<String>::new());
    let http = NewConfig {
        url: "http://konnektor.test".into(),
        ..ru
    };
    assert!(refusals(None, &parse(&http.to_json()))[0].contains("https only"));
}

#[test]
fn set_changes_one_member() {
    let json = config().to_json();
    let json = edit::set(&json, "workplaceId", "W2").unwrap();
    let json = edit::set(&json, "url", "10.0.0.5:8443").unwrap();
    let json = edit::set(&json, "insecureSkipVerify", "true").unwrap();
    let json = edit::set(&json, "userId", "U1").unwrap();
    let kon = parse(&json);
    assert_eq!(kon.workplace_id, "W2");
    assert_eq!(kon.url, "https://10.0.0.5:8443");
    assert!(kon.insecure_skip_verify);
    assert_eq!(kon.user_id.as_deref(), Some("U1"));
    let kon = parse(
        &edit::set(
            &edit::set(&json, "userId", "").unwrap(),
            "insecureSkipVerify",
            "false",
        )
        .unwrap(),
    );
    assert_eq!(kon.user_id, None);
    assert!(!kon.insecure_skip_verify);
}

/// Secrets never come from the command line.
#[test]
fn set_refuses_secrets_and_unknown_members() {
    let json = config().to_json();
    for key in ["credentials.password", "credentials"] {
        assert!(
            edit::set(&json, key, "x").unwrap_err().contains("secret"),
            "{key}"
        );
    }
    assert!(
        edit::set(&json, "trustStore", "x")
            .unwrap_err()
            .contains("settable")
    );
    assert!(
        edit::set(&json, "insecureSkipVerify", "yes")
            .unwrap_err()
            .contains("true or false")
    );
    assert!(edit::set(&json, "url", "ftp://x").is_err());
}

#[test]
fn new_credentials_replace_the_old() {
    let json = with_credentials(
        &config().to_json(),
        &NewCredentials::Pkcs12 {
            data: vec![0x30, 0x03, 0x02, 0x01, 0x03],
            password: "00".into(),
        },
    )
    .unwrap();
    assert_eq!(
        parse(&json).credentials,
        Credentials::Pkcs12 {
            data: vec![0x30, 0x03, 0x02, 0x01, 0x03],
            password: "00".into()
        }
    );
    assert!(!String::from_utf8(json).unwrap().contains("praxis"));
}

/// A new pin replaces the old pins; the trust store's CAs stay.
#[test]
fn a_new_pin_replaces_the_pins_and_keeps_the_cas() {
    let json = NewConfig {
        trust_store: vec![der(SERVER), der(CA)],
        ..config()
    }
    .to_json();
    let kon = parse(&with_pin(&json, &der(OTHER)).unwrap());
    assert_eq!(kon.trust_store, [der(OTHER), der(CA)]);
}
