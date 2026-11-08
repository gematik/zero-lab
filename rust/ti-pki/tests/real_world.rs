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

//! Live tests against gematik's published endpoints: roots.json and the TSL of every
//! environment through the production loading path (`HttpLoader` → `Reloader` →
//! snapshot), and OCSP at real responders. Ignored by default; run them with
//! `just real-world`.
//!
//! The requests go through `curl`: the crate leaves the transport and its TLS to the
//! host, and these tests should not pick a TLS stack for it.
#![cfg(all(
    feature = "load",
    feature = "os",
    feature = "dangerous-nonprod",
    feature = "brainpool"
))]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use futures_lite::future::block_on;
use ti_pki::load::{
    ArtifactRequest, ArtifactResponse, HttpLoader, PostRequest, ReloadOutcome, ReloadPolicy,
    Reloader, ResponseMeta, Source, Transport, TransportError, TransportErrorKind,
};
use ti_pki::ocsp::OcspChecker;
use ti_pki::revocation::ResponderAuthorization;
use ti_pki::{Env, ErrorCode, Timestamp, TrustConfig, TrustStore, profile, roots};

/// A transport over the `curl` CLI, for these tests only.
struct Curl;

impl Curl {
    fn run(args: &[&str], body: Option<&[u8]>) -> Result<Vec<u8>, TransportError> {
        let mut child = Command::new("curl")
            .args(["--silent", "--show-error", "--fail", "--max-time", "60"])
            .args(args)
            .stdin(if body.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| error(e.to_string()))?;
        if let Some(body) = body {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(body)
                .map_err(|e| error(e.to_string()))?;
        }
        let out = child.wait_with_output().map_err(|e| error(e.to_string()))?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(error(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }
}

fn error(message: String) -> TransportError {
    TransportError {
        kind: TransportErrorKind::Network,
        message,
        retryable: true,
    }
}

impl Transport for Curl {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        Ok(ArtifactResponse::Fresh {
            body: Curl::run(&[req.url], None)?,
            meta: ResponseMeta {
                etag: None,
                last_modified: None,
                max_age: None,
                source: Source::Http,
            },
        })
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        let content_type = format!("Content-Type: {}", req.content_type);
        let accept = format!("Accept: {}", req.accept);
        Curl::run(
            &[
                "-H",
                &content_type,
                "-H",
                &accept,
                "--data-binary",
                "@-",
                req.url,
            ],
            Some(req.body),
        )
    }
}

/// The live roots.json and TSL of `env`, verified and loaded the way a service does.
fn live_store(env: Env) -> (TrustConfig, Arc<TrustStore>) {
    let config = TrustConfig::preset(env);
    let loader = HttpLoader::new(&config, Curl, Timestamp::now);
    let reloader = Reloader::new(
        config.clone(),
        env.tier(),
        loader,
        Timestamp::now,
        ReloadPolicy::default(),
    )
    .unwrap();
    let outcome = block_on(reloader.tick());
    assert!(
        matches!(outcome, ReloadOutcome::Swapped { .. }),
        "{env}: {outcome:?}"
    );
    (config, reloader.handle().snapshot().unwrap())
}

#[test]
#[ignore = "network: gematik download endpoints"]
fn live_trust_material_of_every_environment() {
    for env in [Env::Prod, Env::Ref, Env::Test] {
        let (config, store) = live_store(env);
        let embedded = roots::load(&config, Timestamp::now()).unwrap().trusted;
        println!(
            "{env}: {} roots ({} embedded), {} TSL CAs chain to them",
            store.len(),
            embedded.len(),
            store.intermediates().len()
        );
        assert!(
            store.len() >= embedded.len(),
            "{env}: fewer roots than embedded"
        );
        assert!(store.intermediates().len() > 50, "{env}: too few TSL CAs");
    }
}

/// A real SMC-B of the reference environment: chain from the live TSL, profile picked
/// automatically, OCSP for the end entity at its TSP and for nothing else (VALID-008).
/// The TSP answers with a responder certified by another of its CAs, which the TSL lists
/// as an OCSP service (since October 2026): authorized by the listing, with the warning
/// `ocsp_responder_not_rfc6960`. The test pins exactly that, so it notices when gematik
/// changes either side.
#[test]
#[ignore = "network: gematik download endpoints and OCSP responders"]
fn live_smcb_end_to_end() {
    let (config, store) = live_store(Env::Ref);
    let pem = include_str!("fixtures/admission-1.pem");
    let certs = ti_pki::parse_pem_certificates(pem.as_bytes()).unwrap();
    let selection = profile::select_for_cert(&certs[0]);
    let (Some(profile), Some(t)) = (selection.profile, selection.cert_type) else {
        panic!("no profile: {}", selection.detail)
    };
    assert_eq!(profile.name, "hci-aut");
    let validator = profile.validator(&config, store, t);
    let checker = OcspChecker::new(&config, Curl, Timestamp::now);
    let result = block_on(validator.validate(&certs, Timestamp::now(), &checker)).unwrap();
    for (cert, detail) in result.chain.iter().zip(&result.cert_results) {
        let revocation = detail
            .revocation
            .as_ref()
            .map(|r| (r.status, &r.responder_name));
        println!(
            "{:<11} {} {revocation:?}",
            detail.position,
            cert.subject_cn()
        );
    }
    for error in &result.errors {
        println!("error: {error}");
    }
    for warning in &result.warnings {
        println!("warning: {warning}");
    }
    assert_eq!(result.chain.len(), 3);
    assert!(
        result.cert_results[1..]
            .iter()
            .all(|c| c.revocation.is_none()),
        "no responder is asked about a CA"
    );
    assert!(result.valid, "{:?}", result.errors);
    let ee = result.cert_results[0]
        .revocation
        .as_ref()
        .expect("the end entity was checked");
    assert!(
        matches!(
            ee.authorization,
            Some(ResponderAuthorization::TslListed { .. })
        ),
        "{:?}",
        ee.authorization
    );
    let responder = ee.responder.as_ref().expect("a delegated responder");
    assert_eq!(responder.issuer_cn(), "GEM.KOMP-CA51 TEST-ONLY");
    let warnings: Vec<ErrorCode> = result.warnings.iter().map(|w| w.code).collect();
    assert_eq!(warnings, [ErrorCode::OcspResponderNotRfc6960]);
}
