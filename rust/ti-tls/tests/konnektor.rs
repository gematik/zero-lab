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

//! The Konnektor's trust as the `.kon` file configures it, asked as rustls asks it, with the
//! OpenSSL-generated material of ti-connector-client (`tests/tls/generate.sh` there). A
//! handshake over a socket is ti-client's test (`tests/konnektor_tls.rs`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::CertificateError;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use ti_tls::konnektor::{Trust, Unusable, server_name};

const CA: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/ca.pem");
const SERVER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server.pem");
const OTHER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/other.pem");

/// 2027-01-01T00:00:00Z, within the material's validity.
const NOW: u64 = 1_798_761_600;

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}

fn no_system(
    _: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, rustls::Error> {
    panic!("the operating system's trust is asked only for an empty trust store")
}

/// The server certificate verified for `name` at [`NOW`].
fn verify(trust: &Trust, certificate: &[u8], name: &str) -> Result<(), rustls::Error> {
    let now = UnixTime::since_unix_epoch(Duration::from_secs(NOW));
    let name = ServerName::try_from(name.to_owned()).unwrap();
    trust
        .verifier()
        .verify_server_cert(
            &CertificateDer::from(der(certificate)),
            &[],
            &name,
            &[],
            now,
        )
        .map(|_| ())
}

#[test]
fn a_pinned_certificate_is_trusted_by_equality_whatever_the_name() {
    let trust = Trust::new(&[der(SERVER)], false, no_system).unwrap();
    assert_eq!(verify(&trust, SERVER, "127.0.0.1"), Ok(()));
    assert_eq!(
        verify(&trust, OTHER, "konnektor.test"),
        Err(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
}

#[test]
fn a_ca_chain_must_name_the_server() {
    let trust = Trust::new(&[der(CA)], false, no_system).unwrap();
    assert_eq!(verify(&trust, SERVER, "konnektor.test"), Ok(()));
    let error = verify(&trust, SERVER, "127.0.0.1").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not valid for name \"127.0.0.1\""),
        "{error}"
    );
    assert!(verify(&trust, OTHER, "konnektor.test").is_err());
}

#[test]
fn insecure_skip_verify_accepts_any_certificate() {
    let trust = Trust::new(&[der(CA)], true, no_system).unwrap();
    assert_eq!(verify(&trust, OTHER, "elsewhere.test"), Ok(()));
}

#[test]
fn an_empty_trust_store_is_the_operating_systems() {
    let asked = Arc::new(AtomicUsize::new(0));
    let counted = asked.clone();
    let trust = Trust::new(&[], false, move |provider| {
        counted.fetch_add(1, Ordering::Relaxed);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(der(CA))).unwrap();
        Ok(
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap() as Arc<dyn ServerCertVerifier>,
        )
    })
    .unwrap();
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    assert_eq!(verify(&trust, SERVER, "konnektor.test"), Ok(()));

    let failed = Trust::new(&[], false, |_| {
        Err(rustls::Error::General("no store".into()))
    });
    assert_eq!(
        failed.unwrap_err(),
        Unusable("system trust store: unexpected error: no store".into())
    );
}

#[test]
fn a_trust_store_entry_that_is_no_certificate_is_unusable() {
    let error = Trust::new(&[der(CA), b"junk".to_vec()], false, no_system).unwrap_err();
    assert!(error.0.starts_with("trustStore[1]: "), "{error}");
}

#[test]
fn expected_host_is_the_server_name() {
    assert_eq!(
        server_name(Some("konnektor.test"), "10.0.0.1").unwrap(),
        ServerName::try_from("konnektor.test").unwrap()
    );
    assert_eq!(
        server_name(None, "[fe80::1]").unwrap(),
        ServerName::try_from("fe80::1").unwrap()
    );
    assert!(server_name(Some("not a name"), "10.0.0.1").is_err());
}
