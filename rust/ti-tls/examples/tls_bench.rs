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

//! `just tls-bench`: a cold and a cached verification under each profile of
//! `spec/pki-validation`, on the corpus's chains with their OCSP answers stapled, so no network
//! takes part. Cold is a fresh verifier per handshake; cached is the same chain and host again.
//! The median of each must stay within its budget, or the run fails.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use ti_pki::revocation::Unchecked;
use ti_pki::tls::ServerCheck;
use ti_pki::tsl::Intermediate;
use ti_pki::{CertificateType, TrustConfig, TrustStore};
use ti_tls::{Offline, TiVerifier, WebCheck, WebVerifier};

/// The budgets, as medians on one core of a release build.
const COLD: Duration = Duration::from_millis(5);
const CACHED: Duration = Duration::from_micros(10);

const AT: u64 = 1_767_225_600;

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/pki-validation/testdata")
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(testdata().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn cert(name: &str) -> ti_pki::Certificate {
    ti_pki::parse_pem_certificates(&bytes(name))
        .unwrap()
        .remove(0)
}

fn der(name: &str) -> CertificateDer<'static> {
    CertificateDer::from(cert(name).der().to_vec())
}

fn ti_verifier() -> TiVerifier<Unchecked> {
    let ca = cert("ti-ca.pem");
    let types = vec![(
        ca.clone(),
        vec![CertificateType::from_str("C.FD.TLS-S").unwrap().oid()],
    )];
    let store = TrustStore::new([cert("ti-root.pem")])
        .with_intermediates(vec![Intermediate {
            certificate: ca,
            provider: "TEST-ONLY".into(),
            revoked_since: None,
        }])
        .with_tsl_ca_types_for_tests(types);
    let config = TrustConfig::for_lab_ca(cert("ti-root.pem").der());
    TiVerifier::new(ServerCheck::new(config, Some(Arc::new(store))), Unchecked)
}

fn web_verifier() -> WebVerifier<Offline> {
    WebVerifier::new(WebCheck::new([der("web-root.pem")]), Offline)
}

/// The median of `runs` timings of `handshake`, which must succeed.
fn median(runs: usize, mut handshake: impl FnMut()) -> Duration {
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            handshake();
            start.elapsed()
        })
        .collect();
    times.sort_unstable();
    times[runs / 2]
}

fn main() -> ExitCode {
    let at = UnixTime::since_unix_epoch(Duration::from_secs(AT));
    let now = ti_pki::Timestamp(AT);
    let ti = ti_verifier();
    let web = web_verifier();
    let ti_chain = [der("ti-good.pem"), der("ti-ca.pem")];
    let web_chain = [der("web-p256.pem"), der("web-ca.pem")];
    let ti_stapled = bytes("ocsp/ti-good-good.der");
    let web_stapled = bytes("ocsp/web-p256-good.der");
    let ti_host = ServerName::try_from("svc.ti.test").unwrap();
    let web_host = ServerName::try_from("www.web.test").unwrap();
    // Cold: the whole check, never the cache. Cached: the handshake again after the first.
    let rows = [
        (
            "ti",
            median(500, || {
                assert!(
                    ti.verify(
                        &ti_chain[0],
                        &ti_chain[1..],
                        "svc.ti.test",
                        &ti_stapled,
                        now
                    )
                    .is_valid()
                );
            }),
            cached(&ti, &ti_chain, &ti_host, &ti_stapled, at),
        ),
        (
            "web",
            median(500, || {
                assert!(
                    web.verify(
                        &web_chain[0],
                        &web_chain[1..],
                        "www.web.test",
                        &web_stapled,
                        now
                    )
                    .is_valid()
                );
            }),
            cached(&web, &web_chain, &web_host, &web_stapled, at),
        ),
    ];
    let mut within = true;
    println!("profile  cold (budget {COLD:?})  cached (budget {CACHED:?})");
    for (profile, cold, cached) in rows {
        let ok = cold <= COLD && cached <= CACHED;
        within &= ok;
        println!(
            "{profile:<8} {:<22} {:<10} {}",
            format!("{cold:?}"),
            format!("{cached:?}"),
            if ok { "ok" } else { "OVER BUDGET" }
        );
    }
    if within {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The median of handshakes that find their verdict in the cache.
fn cached(
    verifier: &dyn ServerCertVerifier,
    chain: &[CertificateDer<'static>; 2],
    host: &ServerName<'static>,
    stapled: &[u8],
    at: UnixTime,
) -> Duration {
    let handshake = || {
        verifier
            .verify_server_cert(&chain[0], &chain[1..], host, stapled, at)
            .unwrap_or_else(|e| panic!("{e}"));
    };
    handshake();
    median(20_000, handshake)
}
