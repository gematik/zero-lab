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

//! The TLS of a TCP listener without a token: what start-up refuses (servers.md rules 17 and
//! 29) and the profile (spec/pki-validation TLSV-010 to 012).

#![cfg(feature = "grpc")]

mod support;

use std::time::SystemTime;

use support::pki::{Ca, dns, expired, loopback, valid_for};
use ti_hsm_proxy::transport::tls::{Clients, TlsListener};

fn refused(chain: &str, key: &str, clients: Option<Clients<'_>>) -> String {
    match TlsListener::new(chain.as_bytes(), key.as_bytes(), clients, SystemTime::now()) {
        Ok(_) => panic!("the material was taken"),
        Err(e) => e.to_string(),
    }
}

/// servers.md rule 17: the listener does not start on an expired certificate, a key of
/// another certificate, a CA file without certificates, or mTLS without an allowlist; it
/// starts on a matching pair, and with a CA and an allowlist it is mutual.
#[test]
fn servers_rule_17_tls_material_that_does_not_hold_does_not_start() {
    let ca = Ca::new("hsm-proxy listener CA");
    let server = ca.issue(
        "hsm-proxy",
        vec![dns("localhost"), loopback()],
        valid_for(1),
    );
    let other = ca.issue("other", vec![dns("other")], valid_for(1));
    let old = ca.issue("hsm-proxy", vec![dns("localhost")], expired());

    assert!(refused(&old.cert, &old.key, None).contains("expired"));
    let mismatch = refused(&server.cert, &other.key, None);
    assert!(mismatch.contains("does not match"), "{mismatch}");
    assert!(refused(&server.cert, "not a key", None).contains("key file"));
    assert!(refused("", &server.key, None).contains("no certificate"));
    let allow = || vec!["spiffe://zeta/pep".to_owned()];
    assert!(
        refused(
            &server.cert,
            &server.key,
            Some(Clients {
                ca: b"",
                allow: allow()
            })
        )
        .contains("CA file holds no certificate")
    );
    assert!(
        refused(
            &server.cert,
            &server.key,
            Some(Clients {
                ca: ca.cert.as_bytes(),
                allow: Vec::new()
            })
        )
        .contains("allowlist")
    );

    let tls = TlsListener::new(
        server.cert.as_bytes(),
        server.key.as_bytes(),
        None,
        SystemTime::now(),
    )
    .unwrap();
    assert!(!tls.is_mutual());
    let mtls = TlsListener::new(
        server.cert.as_bytes(),
        server.key.as_bytes(),
        Some(Clients {
            ca: ca.cert.as_bytes(),
            allow: allow(),
        }),
        SystemTime::now(),
    )
    .unwrap();
    assert!(mtls.is_mutual());
}

/// spec/pki-validation TLSV-010 to 012: the listener offers the suites and groups of the
/// clients' profile in ti-tls, and no other.
#[test]
fn tlsv_010_to_012_the_listener_has_the_profile_of_the_clients() {
    let names = |provider: &rustls::crypto::CryptoProvider| {
        let suites: Vec<_> = provider
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        let groups: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        (suites, groups)
    };
    assert_eq!(
        names(&ti_hsm_proxy::transport::tls::provider()),
        names(&ti_tls::verifier::provider())
    );
}
