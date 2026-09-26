//! Live tests against gematik's published endpoints: roots.json and the TSL of every
//! environment through the production loading path (`HttpLoader` → `Reloader` →
//! snapshot), and OCSP at real responders. Ignored by default; run them with
//! `just real-world`.
//!
//! The requests go through `curl`: the crate's reqwest adapter leaves TLS to the
//! application, and these tests should not pick a TLS stack for it.
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
    Reloader, ResponseMeta, Source, SystemClock, Transport, TransportError, TransportErrorKind,
};
use ti_pki::ocsp::OcspChecker;
use ti_pki::revocation::{RevocationChecker, RevocationStatus};
use ti_pki::{Clock, Env, ErrorCode, TrustConfig, TrustStore, profile, roots};

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
    let loader = HttpLoader::new(&config, Curl, SystemClock);
    let reloader = Reloader::new(
        config.clone(),
        env.tier(),
        loader,
        SystemClock,
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
        let embedded = roots::load(&config, SystemClock.now()).unwrap().trusted;
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
/// automatically, OCSP for the CA at the root responder and for the end entity at its
/// TSP. The TSP answers with a delegate of another CA (ehca, GEM.KOMP-CA51), which
/// RFC 6960 does not authorize; that is the only failure accepted here, so the test
/// notices when gematik changes either side.
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
    assert_eq!(profile.name, "smb-aut");
    let validator = profile.validator(&config, store, t);
    let checker = OcspChecker::new(&config, Curl, SystemClock);
    let result = block_on(validator.validate(&certs, SystemClock.now(), &checker)).unwrap();
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
    assert_eq!(result.chain.len(), 3);
    let ca = result.cert_results[1]
        .revocation
        .as_ref()
        .expect("the CA was checked");
    assert_eq!(
        ca.status,
        RevocationStatus::Good,
        "TUC_PKI_006 at the root responder"
    );
    let unexpected: Vec<_> = result
        .errors
        .iter()
        .filter(|e| {
            !(e.code == ErrorCode::OcspResponderUntrusted && e.message.contains("GEM.KOMP-CA51"))
        })
        .collect();
    assert!(unexpected.is_empty(), "{unexpected:?}");
}

/// A production SubCA from the live TSL, checked at the production root responder.
#[test]
#[ignore = "network: gematik download endpoints and the production root responder"]
fn live_prod_sub_ca_at_its_root() {
    let (config, store) = live_store(Env::Prod);
    let checker = OcspChecker::new(&config, Curl, SystemClock);
    let now = SystemClock.now();
    let ca = store
        .intermediates()
        .iter()
        .find(|ca| ca.is_valid_at(now) && !ca.ocsp_urls().is_empty())
        .expect("a current CA with a responder");
    let root = store
        .roots()
        .iter()
        .find(|root| {
            root.subject_der() == ca.issuer_der()
                && ca.verify_signed_by(root, &config.algorithms).is_ok()
        })
        .expect("its root");
    let result = block_on(checker.check(ca, root)).unwrap();
    println!(
        "{} at {}: {} by {}",
        ca.subject_cn(),
        result.responder_url,
        result.status,
        result.responder_name
    );
    assert_eq!(result.status, RevocationStatus::Good);
}
