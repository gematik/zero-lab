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

//! The IDP-Dienst's certificates checked against the TSL, as gemSpec_IDP_Dienst asks of
//! every client: the idpd-sig profile (C.FD.SIG with the role `oid_idpd`), the chain to
//! the environment's TSL CAs, and OCSP. One trust material load serves both
//! certificates of a run.

use core::fmt;
use std::cell::{OnceCell, RefCell};
use std::sync::Arc;

use ti_idpd_client::trust::{CertificateTrust, Checked, IdpCertificate};
use ti_pki::ocsp::OcspChecker;
use ti_pki::profile::IDPD_SIG;
use ti_pki::revocation::{RevocationMode, Unchecked};
use ti_pki::{Certificate, CertificateType, Env, Timestamp, TrustConfig, TrustStore};

use crate::error::Error;
use crate::pki::verify::environment;
use crate::trust::Session;

/// How the IDP's certificates are judged.
pub enum IdpTrust<'a, E> {
    /// Against the TSL of an environment.
    Tsl(Box<TslTrust<'a, E>>),
    /// Not at all; the caller says so.
    Unverified,
}

impl<'a, E: From<Error> + fmt::Display> IdpTrust<'a, E> {
    /// Against the TSL of `env`, or of the environment the certificate shows when `None`,
    /// its trust material loaded through the session `open` gives once it is needed.
    pub fn tsl(env: Option<Env>, open: impl Fn() -> Result<Session, E> + 'a) -> IdpTrust<'a, E> {
        IdpTrust::Tsl(Box::new(TslTrust {
            env,
            open: Box::new(open),
            loaded: OnceCell::new(),
            error: RefCell::new(None),
        }))
    }

    /// A failure to load trust material, which a refusal of the flow stands for.
    pub fn take_error(&self) -> Option<E> {
        match self {
            IdpTrust::Tsl(tsl) => tsl.error.borrow_mut().take(),
            IdpTrust::Unverified => None,
        }
    }
}

impl<E: From<Error> + fmt::Display> CertificateTrust for IdpTrust<'_, E> {
    async fn check(
        &self,
        which: IdpCertificate,
        certificate_der: &[u8],
        chain_der: &[Vec<u8>],
    ) -> Result<Checked, String> {
        match self {
            IdpTrust::Tsl(tsl) => tsl.check(which, certificate_der, chain_der).await,
            IdpTrust::Unverified => Ok(Checked::Unchecked),
        }
    }
}

/// The TSL check.
pub struct TslTrust<'a, E> {
    env: Option<Env>,
    open: Box<dyn Fn() -> Result<Session, E> + 'a>,
    /// The material of the environment checked first; both certificates share it.
    loaded: OnceCell<Loaded>,
    /// Why trust material could not be had, for the caller's error.
    error: RefCell<Option<E>>,
}

struct Loaded {
    env: Env,
    config: TrustConfig,
    store: Arc<TrustStore>,
    session: Session,
}

impl<E: From<Error> + fmt::Display> TslTrust<'_, E> {
    async fn check(
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
        let at = Timestamp::now();
        let loaded = if let Some(loaded) = self.loaded.get() {
            loaded
        } else {
            let loaded = self.load(&certs, at).map_err(|error| {
                let message = error.to_string();
                *self.error.borrow_mut() = Some(error);
                message
            })?;
            self.loaded.get_or_init(|| loaded)
        };
        let mut validator = IDPD_SIG.validator(
            &loaded.config,
            Arc::clone(&loaded.store),
            CertificateType::FdSig,
        );
        let result = if let Some(transport) = loaded.session.transport() {
            let checker = OcspChecker::new(&loaded.config, transport, Timestamp::now)
                .with_store(loaded.session.store());
            validator.validate(&certs, at, &checker).await
        } else {
            validator.revocation = RevocationMode::Disabled;
            validator.validate(&certs, at, &Unchecked).await
        }
        .map_err(|e| e.to_string())?;
        let subject = certs[0].subject_cn().to_owned();
        if result.valid {
            loaded.session.observe(format_args!(
                "{which}: {subject} valid for an IDP-Dienst in {} (idpd-sig, OCSP{})",
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
            ));
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

    fn load(&self, certs: &[Certificate], at: Timestamp) -> Result<Loaded, E> {
        let (env, _) = environment(self.env, certs, at)?;
        let session = (self.open)()?;
        let (config, material) = session.load_env(env, false, None)?;
        session.observe(format_args!(
            "IDP certificates against {env}: {} roots, {} TSL CAs from {}",
            material.info.roots, material.info.intermediates, material.info.source
        ));
        Ok(Loaded {
            env,
            config,
            store: material.store,
            session,
        })
    }
}
