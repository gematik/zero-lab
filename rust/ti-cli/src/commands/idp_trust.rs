//! The IDP-Dienst's certificates checked against the TSL, as gemSpec_IDP_Dienst asks of
//! every client: the idp-sig profile (C.FD.SIG with the role `oid_idpd`), the chain to
//! the environment's TSL CAs, and OCSP. One trust material load serves both
//! certificates of a run.

use std::cell::RefCell;
use std::sync::Arc;

use serde::Serialize;
use ti_idpd::trust::{CertificateTrust, Checked, IdpCertificate};
use ti_pki::load::SystemClock;
use ti_pki::ocsp::OcspChecker;
use ti_pki::profile::IDP_SIG;
use ti_pki::revocation::{RevocationMode, Unchecked};
use ti_pki::{Certificate, CertificateType, Clock, Env, TrustConfig, TrustStore};

use crate::block::block_on;
use crate::cli::{Environment, GlobalArgs};
use crate::error::CliError;
use crate::output::{Output, hex};
use crate::trust::Session;

/// How the IDP's certificates are judged.
pub enum IdpTrust<'a> {
    /// Against the TSL of `env`, or of the environment the certificate shows when `None`.
    Tsl(Box<TslTrust<'a>>),
    /// Not at all (`--idp-unverified`); the report warns.
    Unverified,
}

impl<'a> IdpTrust<'a> {
    /// The check the command line asks for: `unverified`, or the TSL of `env` (`auto`
    /// detects it from the certificate).
    pub fn new(
        unverified: bool,
        env: Option<Environment>,
        global: &'a GlobalArgs,
        out: &'a Output,
    ) -> IdpTrust<'a> {
        if unverified {
            out.verbose(
                1,
                "--idp-unverified: the IDP's certificates are used without a check against the TSL",
            );
            return IdpTrust::Unverified;
        }
        IdpTrust::Tsl(Box::new(TslTrust {
            env: env.and_then(Environment::concrete),
            global,
            out,
            loaded: RefCell::new(None),
            error: RefCell::new(None),
        }))
    }

    /// A failure to load trust material, which a refusal of the flow stands for.
    pub fn take_error(&self) -> Option<CliError> {
        match self {
            IdpTrust::Tsl(tsl) => tsl.error.borrow_mut().take(),
            IdpTrust::Unverified => None,
        }
    }
}

impl CertificateTrust for IdpTrust<'_> {
    fn check(
        &self,
        which: IdpCertificate,
        certificate_der: &[u8],
        chain_der: &[Vec<u8>],
    ) -> Result<Checked, String> {
        match self {
            IdpTrust::Tsl(tsl) => tsl.check(which, certificate_der, chain_der),
            IdpTrust::Unverified => Ok(Checked::Unchecked),
        }
    }
}

/// The TSL check.
pub struct TslTrust<'a> {
    env: Option<Env>,
    global: &'a GlobalArgs,
    out: &'a Output,
    /// The material of the environment checked first; both certificates share it.
    loaded: RefCell<Option<Loaded>>,
    /// Why trust material could not be had, for the command's error.
    error: RefCell<Option<CliError>>,
}

struct Loaded {
    env: Env,
    config: TrustConfig,
    store: Arc<TrustStore>,
    session: Session,
}

impl TslTrust<'_> {
    fn check(
        &self,
        which: IdpCertificate,
        certificate_der: &[u8],
        chain_der: &[Vec<u8>],
    ) -> Result<Checked, String> {
        let certs = std::iter::once(certificate_der)
            .chain(chain_der.iter().map(Vec::as_slice))
            .map(Certificate::from_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let at = SystemClock.now();
        if self.loaded.borrow().is_none() {
            let loaded = self.load(&certs, at).map_err(|error| {
                let message = error.to_string();
                *self.error.borrow_mut() = Some(error);
                message
            })?;
            *self.loaded.borrow_mut() = Some(loaded);
        }
        let loaded = self.loaded.borrow();
        let Some(loaded) = loaded.as_ref() else {
            unreachable!("loaded above");
        };
        let mut validator = IDP_SIG.validator(
            &loaded.config,
            Arc::clone(&loaded.store),
            CertificateType::FdSig,
        );
        let result = block_on(async {
            if let Some(transport) = loaded.session.transport() {
                let checker = OcspChecker::new(&loaded.config, transport, SystemClock)
                    .with_store(loaded.session.store());
                validator.validate(&certs, at, &checker).await
            } else {
                validator.revocation = RevocationMode::Disabled;
                validator.validate(&certs, at, &Unchecked).await
            }
        })
        .map_err(|e| e.to_string())?;
        let subject = certs[0].subject_cn().to_owned();
        if result.valid {
            self.out.verbose(
                1,
                format_args!(
                    "{which}: {subject} valid for an IDP-Dienst in {} (idp-sig, OCSP{})",
                    loaded.env,
                    if result
                        .cert_results
                        .first()
                        .and_then(|r| r.revocation.as_ref())
                        .is_some_and(|r| r.from_cache)
                    {
                        " from the cache"
                    } else {
                        ""
                    }
                ),
            );
            Ok(Checked::Verified)
        } else {
            let reasons: Vec<String> = result
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect();
            Err(format!(
                "{subject} is not valid for an IDP-Dienst in {}: {}",
                loaded.env,
                reasons.join("; ")
            ))
        }
    }

    fn load(&self, certs: &[Certificate], at: ti_pki::Timestamp) -> Result<Loaded, CliError> {
        let choice = match self.env {
            Some(Env::Prod) => Environment::Prod,
            Some(Env::Test) => Environment::Test,
            Some(Env::Dev) => Environment::Dev,
            Some(_) => Environment::Ref,
            None => Environment::Auto,
        };
        let (env, _) = super::verify::environment(choice, certs, at)?;
        let config = super::trust_config(env, false);
        config.validate(env.tier()).map_err(CliError::Trust)?;
        let session = Session::new(self.global, false, self.out)?;
        let material = session.load(&config, env.tier(), None)?;
        self.out.verbose(
            1,
            format_args!(
                "IDP certificates against {env}: {} roots, {} TSL CAs from {}",
                material.info.roots, material.info.intermediates, material.info.source
            ),
        );
        Ok(Loaded {
            env,
            config,
            store: material.store,
            session,
        })
    }
}

/// One of the IDP's certificates as the report shows it.
#[derive(Serialize)]
pub struct CertificateInfo {
    /// `puk_disc_sig` or `puk_idp_sig`.
    pub key: &'static str,
    pub subject: String,
    /// SHA-256 of the DER, hex.
    pub sha256: String,
    /// Checked against the TSL and valid; false when `--idp-unverified`.
    pub verified: bool,
}

/// The report entries for `done`'s certificates.
pub fn certificate_infos(
    certificates: &[ti_idpd::authenticator::CheckedCertificate],
) -> Vec<CertificateInfo> {
    use sha2::{Digest, Sha256};
    certificates
        .iter()
        .map(|c| CertificateInfo {
            key: c.which.as_str(),
            subject: Certificate::from_der(&c.der)
                .map(|cert| cert.subject().to_string())
                .unwrap_or_default(),
            sha256: hex(&Sha256::digest(&c.der)),
            verified: c.checked == Checked::Verified,
        })
        .collect()
}
