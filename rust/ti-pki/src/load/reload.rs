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

//! Hot reload: [`Reloader`] loads, verifies and swaps trust material; everything else
//! reads the current [`TrustStore`] through [`TrustStoreHandle::snapshot`].

use core::time::Duration;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use super::artifact::{Artifact, TrustMaterial};
use super::loader::{LoadError, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use super::verify::{VerifyError, VerifyFn, verify_material};
use crate::revocation::{RevocationChecker, RevocationStatus, Unchecked};
use crate::time::Timestamp;
use crate::tsl_signature::{Sequence, TslError, TslState};
use crate::{Certificate, Error, Tier, TrustConfig, TrustStore};
use ti_cache::Source;

/// The longest a production deployment may keep using trust material it could not
/// refresh. Past it, the TSL may list CAs that have since been withdrawn.
pub const MAX_PROD_HARD_EXPIRY: Duration = Duration::from_hours(24);

/// The longest interval between two checks for a new TSL (GS-A_4899, `spec/tsl-xmldsig`
/// TSLSIG-055).
pub const MAX_RELOAD_INTERVAL: Duration = Duration::from_hours(24);

/// When to reload and how long old material stays usable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadPolicy {
    /// Time between attempts.
    pub interval: Duration,
    /// Up to this much is added to each interval, differently per process, so a fleet
    /// started together does not reload in lockstep.
    pub jitter: Duration,
    /// After a failed reload, material younger than this is served as `Stale`; older
    /// as `Degraded`.
    pub stale_if_error: Duration,
    /// Material older than this is not served at all: [`TrustStoreHandle::snapshot`]
    /// fails.
    pub hard_expiry: Duration,
    /// Reload before the TSL's `NextUpdate`, not just on the interval.
    pub honor_tsl_next_update: bool,
    /// How long before `NextUpdate` that reload is due.
    pub next_update_lead: Duration,
}

impl Default for ReloadPolicy {
    /// Hourly with five minutes of jitter; stale after 6 h of failures, expired at the
    /// production maximum of 24 h; reload an hour before the TSL's `NextUpdate`.
    fn default() -> Self {
        ReloadPolicy {
            interval: Duration::from_hours(1),
            jitter: Duration::from_mins(5),
            stale_if_error: Duration::from_hours(6),
            hard_expiry: MAX_PROD_HARD_EXPIRY,
            honor_tsl_next_update: true,
            next_update_lead: Duration::from_hours(1),
        }
    }
}

impl ReloadPolicy {
    /// Checks the policy for use in `tier`.
    ///
    /// # Errors
    ///
    /// [`Error::InconsistentConfig`] if the interval is zero or exceeds
    /// [`MAX_RELOAD_INTERVAL`], `stale_if_error` exceeds
    /// `hard_expiry`, or, under [`Tier::Prod`], `hard_expiry` exceeds
    /// [`MAX_PROD_HARD_EXPIRY`].
    pub fn validate(&self, tier: Tier) -> Result<(), Error> {
        let inconsistent = |reason| Err(Error::InconsistentConfig { reason });
        if self.interval.is_zero() {
            return inconsistent("reload interval must not be zero");
        }
        if self.interval > MAX_RELOAD_INTERVAL {
            return inconsistent("reload interval exceeds MAX_RELOAD_INTERVAL (24 h)");
        }
        if self.stale_if_error > self.hard_expiry {
            return inconsistent("stale_if_error must not exceed hard_expiry");
        }
        if tier == Tier::Prod && self.hard_expiry > MAX_PROD_HARD_EXPIRY {
            return inconsistent("production hard_expiry exceeds MAX_PROD_HARD_EXPIRY");
        }
        Ok(())
    }
}

/// How usable the current material is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum State {
    /// Nothing loaded yet.
    Uninitialised,
    /// The last reload succeeded and the material is younger than `stale_if_error`.
    Fresh,
    /// The last reload failed; the material is younger than `stale_if_error`.
    Stale,
    /// The material is older than `stale_if_error` but younger than `hard_expiry`.
    Degraded,
    /// The material is older than `hard_expiry` and no longer served.
    Expired,
}

/// A point-in-time report, for health endpoints and metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadStatus {
    /// Increments with every swap; 0 before the first.
    pub generation: u64,
    /// When the current material was obtained from its origin.
    pub fetched_at: Option<Timestamp>,
    /// The current TSL's `NextUpdate`.
    pub tsl_next_update: Option<Timestamp>,
    /// Where the current TSL came from.
    pub source: Option<Source>,
    /// When the last reload was attempted.
    pub last_attempt: Option<Timestamp>,
    /// The most recent failure and when it happened.
    pub last_error: Option<(Timestamp, String)>,
    /// Age of the current material.
    pub staleness: Duration,
    /// See [`State`].
    pub state: State,
    /// `Id` and sequence number of the current TSL, to persist for the next start
    /// (TSLSIG-053); before the first swap, the state the reloader was given.
    pub tsl_state: Option<TslState>,
    /// Warnings about the current TSL: [`no_ocsp_check`](crate::tsl_signature::TslCode::NoOcspCheck)
    /// without a signer status checker, [`validity_warning_1`](crate::tsl_signature::TslCode::ValidityWarning1)
    /// within the grace period.
    pub tsl_warnings: Vec<TslError>,
    /// The current TSL's signer and the TSL signer CA that issued it.
    pub tsl_signer: Option<(Certificate, Certificate)>,
    /// The signer's OCSP status, when it was queried or supplied.
    pub tsl_signer_status: Option<RevocationStatus>,
}

/// What a [`Reloader::tick`] did.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReloadOutcome {
    /// Same material as before, or another tick was already running.
    Unchanged,
    /// New material was verified and is now served.
    Swapped {
        /// The new generation.
        generation: u64,
    },
    /// The reload failed and the previous material is still served.
    KeptStale {
        /// Why the reload failed.
        error: ReloadError,
        /// Age of the material still served.
        stale_for: Duration,
        /// [`State::Stale`] or [`State::Degraded`].
        state: State,
    },
    /// The reload failed and no usable material is left.
    Expired {
        /// Why the reload failed.
        error: ReloadError,
    },
}

/// Why a reload failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReloadError {
    /// No material could be loaded.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// Material was loaded but failed verification. Possible tampering.
    #[error(transparent)]
    Verify(#[from] VerifyError),
    /// Material was loaded but is already older than `hard_expiry`.
    #[error("loaded material is {age:?} old, beyond hard_expiry")]
    TooOld {
        /// Its age.
        age: Duration,
    },
}

/// [`TrustStoreHandle::snapshot`] has no usable material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{}", match .fetched_at {
    Some(_) => "trust material expired",
    None => "no trust material loaded yet",
})]
pub struct Expired {
    /// When the expired material was obtained; `None` if nothing was ever loaded.
    pub fetched_at: Option<Timestamp>,
}

#[derive(Debug)]
struct Current {
    store: Arc<TrustStore>,
    etags: Vec<Option<String>>,
    fetched_at: Timestamp,
    tsl_next_update: Option<Timestamp>,
    tsl_state: Option<TslState>,
    tsl_warnings: Vec<TslError>,
    tsl_signer: Option<(Certificate, Certificate)>,
    tsl_signer_status: Option<RevocationStatus>,
    source: Source,
    generation: u64,
}

impl Current {
    /// The same store, confirmed by a load of `material`.
    fn confirmed(&self, material: &TrustMaterial) -> Self {
        Current {
            store: Arc::clone(&self.store),
            etags: material.etags(),
            fetched_at: self.fetched_at.max(material.fetched_at),
            tsl_next_update: self.tsl_next_update,
            tsl_state: self.tsl_state.clone(),
            tsl_warnings: self.tsl_warnings.clone(),
            tsl_signer: self.tsl_signer.clone(),
            tsl_signer_status: self.tsl_signer_status,
            source: self.source,
            generation: self.generation,
        }
    }
}

#[derive(Debug, Default)]
struct Attempts {
    attempted_at: Option<Timestamp>,
    error: Option<(Timestamp, String)>,
    succeeded: bool,
}

/// Shared read access to the current trust store.
#[derive(Debug)]
pub struct TrustStoreHandle<N> {
    current: RwLock<Option<Arc<Current>>>,
    /// The TSL state given at construction, until the first swap replaces it.
    stored_tsl: Option<TslState>,
    attempts: Mutex<Attempts>,
    now: N,
    stale_if_error: Duration,
    hard_expiry: Duration,
    tsl_grace_period: Duration,
}

impl<N: Fn() -> Timestamp> TrustStoreHandle<N> {
    /// Whether the list in use is past its `NextUpdate` and the grace period. A reload
    /// confirming unchanged material does not verify it again, so a directory rewritten with
    /// the same list would otherwise keep it in use (TSLSIG-054).
    fn overdue(&self, current: &Current) -> bool {
        current
            .tsl_next_update
            .is_some_and(|next_update| (self.now)() >= next_update + self.tsl_grace_period)
    }

    /// The current trust store; cheap, call it per request.
    ///
    /// # Errors
    ///
    /// [`Expired`] before the first successful load, once the material is older than
    /// `hard_expiry`, and once the list is past its `NextUpdate` and the grace period, even
    /// if no reload has run since.
    pub fn snapshot(&self) -> Result<Arc<TrustStore>, Expired> {
        let current = self.current().ok_or(Expired { fetched_at: None })?;
        if (self.now)().since(current.fetched_at) >= self.hard_expiry || self.overdue(&current) {
            return Err(Expired {
                fetched_at: Some(current.fetched_at),
            });
        }
        Ok(Arc::clone(&current.store))
    }

    /// The current [`ReloadStatus`].
    pub fn status(&self) -> ReloadStatus {
        let now = (self.now)();
        let current = self.current();
        let attempts = self.attempts();
        let staleness = current
            .as_ref()
            .map_or(Duration::ZERO, |c| now.since(c.fetched_at));
        let state = match &current {
            None => State::Uninitialised,
            Some(_) if staleness >= self.hard_expiry => State::Expired,
            Some(c) if self.overdue(c) => State::Expired,
            Some(_) if staleness >= self.stale_if_error => State::Degraded,
            Some(_) if attempts.succeeded => State::Fresh,
            Some(_) => State::Stale,
        };
        ReloadStatus {
            generation: current.as_ref().map_or(0, |c| c.generation),
            fetched_at: current.as_ref().map(|c| c.fetched_at),
            tsl_next_update: current.as_ref().and_then(|c| c.tsl_next_update),
            source: current.as_ref().map(|c| c.source),
            last_attempt: attempts.attempted_at,
            last_error: attempts.error.clone(),
            staleness,
            state,
            tsl_state: current
                .as_ref()
                .and_then(|c| c.tsl_state.clone())
                .or_else(|| self.stored_tsl.clone()),
            tsl_warnings: current
                .as_ref()
                .map(|c| c.tsl_warnings.clone())
                .unwrap_or_default(),
            tsl_signer: current.as_ref().and_then(|c| c.tsl_signer.clone()),
            tsl_signer_status: current.as_ref().and_then(|c| c.tsl_signer_status),
        }
    }

    /// The current material. A reader only clones the `Arc` under the lock, so a reload
    /// never waits for a validation, nor a validation for a reload.
    fn current(&self) -> Option<Arc<Current>> {
        // A holder replaces or clones one `Option`: it cannot leave it half-written, so a
        // poisoned lock is safe to reuse.
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn set_current(&self, current: Current) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(current));
    }

    fn attempts(&self) -> MutexGuard<'_, Attempts> {
        // The guarded data is plain bookkeeping that stays consistent even if a holder
        // panicked, so a poisoned lock is safe to reuse.
        self.attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Loads, verifies and swaps trust material. It has no timer of its own: call
/// [`tick`](Self::tick) when [`due`](Self::due), from whatever runtime the application
/// uses.
///
/// The TSL is verified as `spec/tsl-xmldsig` requires before its CAs are used: signature
/// and signer under [`TrustConfig::tsl_signer_anchors`], `NextUpdate` and
/// [`TrustConfig::tsl_grace_period`], and `Id` and sequence number against the list
/// before ([`with_stored_tsl`](Self::with_stored_tsl) carries it across restarts). With a
/// checker from [`with_signer_status`](Self::with_signer_status), the signer's OCSP
/// status too; without, the status reports [`no_ocsp_check`](crate::tsl_signature::TslCode::NoOcspCheck).
/// A list that fails any of it is never swapped in.
pub struct Reloader<L, N, R = Unchecked> {
    config: TrustConfig,
    loader: L,
    handle: TrustStoreHandle<N>,
    policy: ReloadPolicy,
    jitter_seed: RandomState,
    in_flight: AtomicBool,
    verify: VerifyFn,
    signer_status: Option<R>,
}

impl<L, N, R> core::fmt::Debug for Reloader<L, N, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reloader")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<L, N> Reloader<L, N>
where
    L: Loader + MaybeSend + MaybeSync,
    N: Fn() -> Timestamp + MaybeSend + MaybeSync,
{
    /// A reloader for `config` in `tier`, without a signer status checker. Nothing is
    /// loaded until the first [`tick`](Self::tick).
    ///
    /// # Errors
    ///
    /// [`Error::InconsistentConfig`] or [`Error::Der`] if `config` or `policy` fail
    /// validation for `tier`.
    pub fn new(
        config: TrustConfig,
        tier: Tier,
        loader: L,
        now: N,
        policy: ReloadPolicy,
    ) -> Result<Self, Error> {
        config.validate(tier)?;
        policy.validate(tier)?;
        let tsl_grace_period = config.tsl_grace_period;
        Ok(Reloader {
            config,
            loader,
            handle: TrustStoreHandle {
                current: RwLock::new(None),
                stored_tsl: None,
                attempts: Mutex::default(),
                now,
                stale_if_error: policy.stale_if_error,
                hard_expiry: policy.hard_expiry,
                tsl_grace_period,
            },
            policy,
            jitter_seed: RandomState::new(),
            in_flight: AtomicBool::new(false),
            verify: verify_material,
            signer_status: None,
        })
    }
}

impl<L, N, R> Reloader<L, N, R>
where
    L: Loader + MaybeSend + MaybeSync,
    N: Fn() -> Timestamp + MaybeSend + MaybeSync,
    R: RevocationChecker + MaybeSend + MaybeSync,
{
    /// Checks the TSL signer's OCSP status with `checker` before a list is swapped in
    /// (TSLSIG-040 – 042), normally an [`OcspChecker`](crate::ocsp::OcspChecker) over the
    /// loader's network.
    #[must_use]
    pub fn with_signer_status<R2>(self, checker: R2) -> Reloader<L, N, R2> {
        Reloader {
            config: self.config,
            loader: self.loader,
            handle: self.handle,
            policy: self.policy,
            jitter_seed: self.jitter_seed,
            in_flight: self.in_flight,
            verify: self.verify,
            signer_status: Some(checker),
        }
    }

    /// The `Id` and sequence number of the list in use before this process started, as
    /// persisted from [`ReloadStatus::tsl_state`]: an older list is then rejected even
    /// on the first load (TSLSIG-053).
    #[must_use]
    pub fn with_stored_tsl(mut self, state: TslState) -> Self {
        self.handle.stored_tsl = Some(state);
        self
    }

    /// Read access for request handlers.
    pub fn handle(&self) -> &TrustStoreHandle<N> {
        &self.handle
    }

    /// When the next tick is due: the last attempt plus interval and this process's
    /// jitter, or earlier if the TSL's `NextUpdate` (less the lead) comes first. Now,
    /// if nothing was attempted yet.
    pub fn next_due(&self) -> Timestamp {
        let Some(last) = self.handle.attempts().attempted_at else {
            return (self.handle.now)();
        };
        let periodic = last + self.policy.interval + self.jitter(last);
        let deadline = self
            .handle
            .current()
            .and_then(|c| c.tsl_next_update)
            .filter(|_| self.policy.honor_tsl_next_update)
            .map(|next_update| next_update - self.policy.next_update_lead);
        deadline.map_or(periodic, |d| d.min(periodic))
    }

    /// Time left until the next tick is due; zero if it is due already.
    pub fn until_due(&self) -> Duration {
        self.next_due().since((self.handle.now)())
    }

    /// Whether a tick is due now.
    pub fn due(&self) -> bool {
        (self.handle.now)() >= self.next_due()
    }

    /// One reload attempt. Single-flight: a tick that starts while another is running
    /// returns [`ReloadOutcome::Unchanged`] at once. Always records the attempt in the
    /// status.
    pub async fn tick(&self) -> ReloadOutcome {
        if self.in_flight.swap(true, Ordering::AcqRel) {
            return ReloadOutcome::Unchanged;
        }
        let _in_flight = InFlight(&self.in_flight);

        let loaded = self.loader.load_all().await;
        let now = (self.handle.now)();
        self.handle.attempts().attempted_at = Some(now);

        let material = match loaded {
            Ok(material) => material,
            Err(error) => return self.fail(now, error.into()),
        };
        let age = now.since(material.fetched_at);
        if age >= self.policy.hard_expiry {
            return self.fail(now, ReloadError::TooOld { age });
        }
        let current = self.handle.current();
        if let Some(current) = &current
            && same_etags(&current.etags, &material)
        {
            return self.confirm(current, &material);
        }
        let stored = current
            .as_ref()
            .and_then(|c| c.tsl_state.clone())
            .or_else(|| self.handle.stored_tsl.clone());
        let mut outcome = (self.verify)(&self.config, &material, now, stored.as_ref());
        let mut material = material;
        // The set travels over plain HTTP and is cached before it is verified: a list and a
        // signature of different states, or one garbage answer, must not go on failing
        // until the entry ages out. So a set that fails is fetched once more (TSLDET-013).
        if matches!(&outcome, Err(error) if error.tsl.is_some()) {
            if let Err(error) = self.loader.revalidate().await {
                return self.fail(now, error.into());
            }
            material = match self.loader.load_all().await {
                Ok(material) => material,
                Err(error) => return self.fail(now, error.into()),
            };
            outcome = (self.verify)(&self.config, &material, now, stored.as_ref());
        }
        let mut verified = match outcome {
            Ok(verified) => verified,
            Err(error) => return self.fail(now, error.into()),
        };
        // The list in use, under new validators: nothing to swap and nothing to ask.
        if verified.sequence == Sequence::Same
            && let Some(current) = &current
        {
            return self.confirm(current, &material);
        }
        // A status supplied with the list (TSLDET-020) needs no network query; a stale
        // one left `signer_status` empty for the checker to fill (TSLDET-021).
        if let (Some(checker), Some(tsl)) = (&self.signer_status, verified.tsl.as_mut())
            && tsl.signer_status.is_none()
            && let Err(error) = tsl.check_signer_status(checker).await
        {
            return self.fail((self.handle.now)(), VerifyError::from(error).into());
        }
        self.swap(&material, verified)
    }

    /// Keeps the current store, confirmed by `material`.
    fn confirm(&self, current: &Current, material: &TrustMaterial) -> ReloadOutcome {
        self.handle.set_current(current.confirmed(material));
        self.handle.attempts().succeeded = true;
        ReloadOutcome::Unchanged
    }

    fn swap(&self, material: &TrustMaterial, verified: super::Verified) -> ReloadOutcome {
        let generation = self.handle.current().map_or(0, |c| c.generation) + 1;
        let tsl_meta = material
            .meta(Artifact::Tsl)
            .expect("the list is always present");
        let (tsl_state, tsl_warnings) = verified.tsl.as_ref().map_or_else(
            || (None, Vec::new()),
            |tsl| (Some(TslState::of(&tsl.tsl)), tsl.warnings.clone()),
        );
        let tsl_signer = verified
            .tsl
            .as_ref()
            .map(|tsl| (tsl.signer.clone(), tsl.anchor.clone()));
        let tsl_signer_status = verified
            .tsl
            .as_ref()
            .and_then(|tsl| tsl.signer_status.as_ref().map(|r| r.status));
        self.handle.set_current(Current {
            tsl_next_update: verified.tsl_next_update,
            tsl_state,
            tsl_warnings,
            tsl_signer,
            tsl_signer_status,
            store: Arc::new(TrustStore::from_verified(verified)),
            etags: material.etags(),
            fetched_at: material.fetched_at,
            source: tsl_meta.source,
            generation,
        });
        self.handle.attempts().succeeded = true;
        ReloadOutcome::Swapped { generation }
    }

    fn fail(&self, now: Timestamp, error: ReloadError) -> ReloadOutcome {
        {
            let mut attempts = self.handle.attempts();
            attempts.succeeded = false;
            attempts.error = Some((now, error.to_string()));
        }
        let Some(current) = self.handle.current() else {
            return ReloadOutcome::Expired { error };
        };
        let stale_for = now.since(current.fetched_at);
        if stale_for >= self.policy.hard_expiry {
            ReloadOutcome::Expired { error }
        } else {
            let state = if stale_for < self.policy.stale_if_error {
                State::Stale
            } else {
                State::Degraded
            };
            ReloadOutcome::KeptStale {
                error,
                stale_for,
                state,
            }
        }
    }

    fn jitter(&self, last_attempt: Timestamp) -> Duration {
        let span = self.policy.jitter.as_secs();
        if span == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs(self.jitter_seed.hash_one(last_attempt.0) % (span + 1))
    }

    #[cfg(test)]
    pub(crate) fn with_verifier(mut self, verify: VerifyFn) -> Self {
        self.verify = verify;
        self
    }
}

/// Whether `material` is what `current` was built from: roots.json and the list carry
/// the same validators, and the detached files are the same, present or absent alike.
fn same_etags(current: &[Option<String>], material: &TrustMaterial) -> bool {
    let new = material.etags();
    current.len() == new.len()
        && current[..2].iter().all(Option::is_some)
        && current.iter().zip(&new).all(|(old, new)| old == new)
}

struct InFlight<'a>(&'a AtomicBool);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use futures_lite::future::{block_on, yield_now, zip};

    use super::*;
    #[cfg(any(feature = "dangerous-nonprod", feature = "brainpool"))]
    use crate::load::Detached;
    use crate::load::{Conditional, Fetched, FixedClock, Meta, Verified};

    const HOUR: Duration = Duration::from_hours(1);
    const T0: Timestamp = Timestamp(1_000_000);

    /// Plays back scripted `load_all` results; yields once per call so concurrent ticks
    /// overlap.
    struct VecLoader {
        script: Mutex<VecDeque<Result<TrustMaterial, LoadError>>>,
        calls: AtomicUsize,
    }

    impl VecLoader {
        fn new(script: impl IntoIterator<Item = Result<TrustMaterial, LoadError>>) -> Self {
            VecLoader {
                script: Mutex::new(script.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Loader for VecLoader {
        async fn fetch(
            &self,
            artifact: Artifact,
            _: Conditional<'_>,
        ) -> Result<Fetched, LoadError> {
            Err(LoadError::Unavailable(artifact))
        }

        async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            yield_now().await;
            self.script
                .lock()
                .unwrap()
                .pop_front()
                .expect("script exhausted")
        }
    }

    /// Accepts anything except roots `tampered`; a TSL body that is a number is its
    /// `NextUpdate`.
    fn test_verify(
        _: &TrustConfig,
        m: &TrustMaterial,
        _: Timestamp,
        _: Option<&TslState>,
    ) -> Result<Verified, VerifyError> {
        if m.roots == b"tampered" {
            return Err(VerifyError::new("roots do not chain to the anchor"));
        }
        let tsl_next_update = std::str::from_utf8(&m.tsl)
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Timestamp);
        Ok(Verified {
            roots: Vec::new(),
            intermediates: Vec::new(),
            tsl_next_update,
            ocsp_responders: Vec::new(),
            ca_types: Vec::new(),
            tsl: None,
            sequence: Sequence::Newer,
        })
    }

    fn material(tag: &str, fetched_at: Timestamp) -> TrustMaterial {
        material_with_tsl(tag, b"tsl".to_vec(), fetched_at)
    }

    fn material_with_tsl(tag: &str, tsl: Vec<u8>, fetched_at: Timestamp) -> TrustMaterial {
        let meta = |etag: String| Meta {
            etag: Some(etag),
            last_modified: None,
            fetched_at,
            max_age: None,
            source: Source::Http,
        };
        let roots = if tag == "tampered" {
            b"tampered".to_vec()
        } else {
            b"roots".to_vec()
        };
        TrustMaterial::new(
            roots,
            meta(format!("r-{tag}")),
            tsl,
            meta(format!("t-{tag}")),
        )
    }

    fn policy() -> ReloadPolicy {
        ReloadPolicy {
            interval: HOUR,
            jitter: Duration::ZERO,
            stale_if_error: 6 * HOUR,
            hard_expiry: 24 * HOUR,
            honor_tsl_next_update: true,
            next_update_lead: HOUR,
        }
    }

    fn reloader(
        clock: &FixedClock,
        script: impl IntoIterator<Item = Result<TrustMaterial, LoadError>>,
    ) -> Reloader<VecLoader, impl Fn() -> Timestamp + '_> {
        Reloader::new(
            crate::config::tests::nist_prod_config(),
            Tier::Prod,
            VecLoader::new(script),
            move || clock.now(),
            policy(),
        )
        .unwrap()
        .with_verifier(test_verify)
    }

    fn offline() -> LoadError {
        LoadError::Offline(Artifact::Tsl)
    }

    /// TSLDET-013: a list under the signature of another state is not the end: the set
    /// is fetched once more, and only a second failure fails the tick.
    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_013_a_signature_that_does_not_fit_refetches_the_set_once() {
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-detached/testdata/"
        );
        let read = |name: &str| std::fs::read(format!("{base}{name}")).unwrap();
        let captured_at = Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap();
        let config = TrustConfig::preset(crate::Env::Ref);
        let meta = |etag: &str| Meta {
            etag: Some(etag.into()),
            last_modified: None,
            fetched_at: captured_at,
            max_age: None,
            source: Source::Http,
        };
        let set = |tag: &str, signature: Vec<u8>| {
            TrustMaterial::new(
                config.roots.to_vec(),
                meta(tag),
                read("ref/ECC-RSA_TSL-ref.xml"),
                meta(tag),
            )
            .with_detached(Some(Detached {
                signature,
                signature_meta: meta(tag),
                signer_status: None,
            }))
        };
        let other = read("prod/ECC-RSA_TSL.sig");
        let good = read("ref/ECC-RSA_TSL-ref.sig");
        let clock = FixedClock::new(captured_at);
        let refetched = Reloader::new(
            config.clone(),
            Tier::NonProd,
            VecLoader::new([Ok(set("a", other.clone())), Ok(set("b", good))]),
            || clock.now(),
            policy(),
        )
        .unwrap();
        assert!(matches!(
            block_on(refetched.tick()),
            ReloadOutcome::Swapped { .. }
        ));

        let still_wrong = Reloader::new(
            config.clone(),
            Tier::NonProd,
            VecLoader::new([Ok(set("a", other.clone())), Ok(set("b", other))]),
            || clock.now(),
            policy(),
        )
        .unwrap();
        assert!(!matches!(
            block_on(still_wrong.tick()),
            ReloadOutcome::Swapped { .. }
        ));

        // One unauthenticated garbage answer in the cache heals the same way (TSLDET-013).
        let healed = Reloader::new(
            config.clone(),
            Tier::NonProd,
            VecLoader::new([
                Ok(set("a", b"<html>captive portal</html>".to_vec())),
                Ok(set("b", read("ref/ECC-RSA_TSL-ref.sig"))),
            ]),
            || clock.now(),
            policy(),
        )
        .unwrap();
        assert!(matches!(
            block_on(healed.tick()),
            ReloadOutcome::Swapped { .. }
        ));
    }

    /// TSLDET-013 through the real stack: one garbage answer on plain HTTP lands in the
    /// cache before it is verified, and the same tick replaces it once the origin is healthy.
    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_013_a_garbage_signature_does_not_poison_the_cache() {
        use crate::load::{
            ArtifactResponse, CachePolicy, CachingLoader, HttpLoader, MemoryCacheStore,
            MockTransport, ResponseMeta, content_etag,
        };
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-detached/testdata/"
        );
        let read = |name: &str| std::fs::read(format!("{base}{name}")).unwrap();
        let fresh = |body: Vec<u8>| {
            Ok(ArtifactResponse::Fresh {
                body,
                meta: ResponseMeta {
                    etag: None,
                    last_modified: None,
                    max_age: None,
                    source: Source::Http,
                },
            })
        };
        let xml = read("ref/ECC-RSA_TSL-ref.xml");
        let hash = content_etag(&xml).trim_start_matches("sha256:").to_owned();
        let config = TrustConfig::preset(crate::Env::Ref);
        let transport = MockTransport::new([
            fresh(config.roots.to_vec()),
            fresh(hash.clone().into_bytes()),
            fresh(xml.clone()),
            fresh(b"<html>captive portal</html>".to_vec()),
            fresh(read("ref/ECC-RSA_TSL-ref.ocsp")),
            fresh(hash.into_bytes()),
            fresh(xml),
            fresh(read("ref/ECC-RSA_TSL-ref.sig")),
            fresh(read("ref/ECC-RSA_TSL-ref.ocsp")),
        ]);
        let clock = FixedClock::new(Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap());
        let store = MemoryCacheStore::default();
        let loader = CachingLoader::new(
            HttpLoader::new(&config, &transport, || clock.now()),
            &store,
            || clock.now(),
            CachePolicy::default(),
        );
        let r = Reloader::new(
            config.clone(),
            Tier::NonProd,
            loader,
            || clock.now(),
            policy(),
        )
        .unwrap();
        let outcome = block_on(r.tick());
        assert!(
            matches!(outcome, ReloadOutcome::Swapped { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            r.handle().status().tsl_signer_status,
            Some(RevocationStatus::Good)
        );
    }

    /// TSLDET-021: a status supplied with the list makes the network query unnecessary.
    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn tsldet_021_reloader_skips_the_network_checker_when_the_status_was_supplied() {
        struct NeverAsked;
        impl RevocationChecker for NeverAsked {
            async fn check(
                &self,
                _: &Certificate,
                _: &Certificate,
                _: &TrustStore,
            ) -> Result<crate::RevocationResult, crate::ValidationError> {
                panic!("the network checker must not be asked when the status was supplied");
            }
        }
        let base = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref."
        );
        let read = |suffix: &str| std::fs::read(format!("{base}{suffix}")).unwrap();
        let captured_at = Timestamp::parse_rfc3339("2026-11-01T16:47:42Z").unwrap();
        let config = TrustConfig::preset(crate::Env::Ref);
        let meta = |etag: &str| Meta {
            etag: Some(etag.into()),
            last_modified: None,
            fetched_at: captured_at,
            max_age: None,
            source: Source::Http,
        };
        let material = TrustMaterial::new(config.roots.to_vec(), meta("r"), read("xml"), meta("t"))
            .with_detached(Some(Detached {
                signature: read("sig"),
                signature_meta: meta("s"),
                signer_status: Some((read("ocsp"), meta("o"))),
            }));
        let clock = FixedClock::new(captured_at);
        let r = Reloader::new(
            config,
            Tier::NonProd,
            VecLoader::new([Ok(material)]),
            || clock.now(),
            policy(),
        )
        .unwrap()
        .with_signer_status(NeverAsked);
        assert!(matches!(block_on(r.tick()), ReloadOutcome::Swapped { .. }));
        assert_eq!(
            r.handle().status().tsl_signer_status,
            Some(RevocationStatus::Good)
        );
    }

    #[test]
    fn first_load_swaps_and_same_etags_are_unchanged() {
        let clock = FixedClock::new(T0);
        let r = reloader(
            &clock,
            [Ok(material("a", T0)), Ok(material("a", T0 + HOUR))],
        );
        assert_eq!(r.handle().status().state, State::Uninitialised);
        assert!(r.handle().snapshot().is_err());

        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::Swapped { generation: 1 }
        ));
        r.handle().snapshot().unwrap();

        clock.advance(HOUR);
        assert!(matches!(block_on(r.tick()), ReloadOutcome::Unchanged));
        let status = r.handle().status();
        assert_eq!(status.generation, 1);
        assert_eq!(status.fetched_at, Some(T0 + HOUR));
        assert_eq!(status.state, State::Fresh);
    }

    #[test]
    fn swap_increments_generation_and_replaces_the_store() {
        let clock = FixedClock::new(T0);
        let r = reloader(&clock, [Ok(material("a", T0)), Ok(material("b", T0))]);
        block_on(r.tick());
        let first = r.handle().snapshot().unwrap();
        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::Swapped { generation: 2 }
        ));
        assert!(!Arc::ptr_eq(&first, &r.handle().snapshot().unwrap()));
    }

    #[test]
    fn verify_failure_keeps_the_old_store() {
        let clock = FixedClock::new(T0);
        let r = reloader(
            &clock,
            [Ok(material("a", T0)), Ok(material("tampered", T0))],
        );
        block_on(r.tick());
        let before = r.handle().snapshot().unwrap();
        let outcome = block_on(r.tick());
        assert!(matches!(
            outcome,
            ReloadOutcome::KeptStale {
                error: ReloadError::Verify(_),
                state: State::Stale,
                ..
            }
        ));
        assert!(Arc::ptr_eq(&before, &r.handle().snapshot().unwrap()));
        let status = r.handle().status();
        assert_eq!(status.generation, 1);
        assert!(status.last_error.unwrap().1.contains("do not chain"));
    }

    #[test]
    fn states_follow_the_policy_boundaries() {
        let clock = FixedClock::new(T0);
        let r = reloader(
            &clock,
            [
                Ok(material("a", T0)),
                Err(offline()),
                Err(offline()),
                Err(offline()),
            ],
        );
        block_on(r.tick());
        assert_eq!(r.handle().status().state, State::Fresh);

        clock.advance(HOUR);
        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::KeptStale {
                state: State::Stale,
                ..
            }
        ));
        assert_eq!(r.handle().status().state, State::Stale);

        clock.set(T0 + 6 * HOUR);
        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::KeptStale {
                state: State::Degraded,
                ..
            }
        ));
        assert_eq!(r.handle().status().state, State::Degraded);
        r.handle().snapshot().unwrap();

        clock.set(T0 + 24 * HOUR);
        assert!(matches!(block_on(r.tick()), ReloadOutcome::Expired { .. }));
        assert_eq!(r.handle().status().state, State::Expired);
        assert_eq!(
            r.handle().snapshot().unwrap_err(),
            Expired {
                fetched_at: Some(T0)
            }
        );
    }

    #[test]
    fn snapshot_expires_without_a_tick() {
        let clock = FixedClock::new(T0);
        let r = reloader(&clock, [Ok(material("a", T0))]);
        block_on(r.tick());
        clock.advance(24 * HOUR);
        assert!(r.handle().snapshot().is_err());
    }

    #[test]
    fn next_due_honours_tsl_next_update() {
        let clock = FixedClock::new(T0);
        let next_update = T0 + Duration::from_mins(90);
        let tsl = next_update.0.to_string().into_bytes();
        let r = reloader(&clock, [Ok(material_with_tsl("a", tsl, T0))]);
        assert_eq!(r.next_due(), T0);
        assert!(r.due());
        block_on(r.tick());
        // NextUpdate in 90 min less the 60 min lead beats the hourly interval.
        assert_eq!(r.next_due(), T0 + Duration::from_mins(30));
        assert!(!r.due());
    }

    #[test]
    fn next_due_is_the_interval_without_next_update() {
        let clock = FixedClock::new(T0);
        let r = reloader(&clock, [Ok(material("a", T0))]);
        block_on(r.tick());
        assert_eq!(r.next_due(), T0 + HOUR);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let clock = FixedClock::new(T0);
        let r = Reloader::new(
            crate::config::tests::nist_prod_config(),
            Tier::Prod,
            VecLoader::new([Ok(material("a", T0))]),
            || clock.now(),
            ReloadPolicy {
                jitter: Duration::from_mins(5),
                ..policy()
            },
        )
        .unwrap()
        .with_verifier(test_verify);
        block_on(r.tick());
        let due = r.next_due();
        assert!(due >= T0 + HOUR && due <= T0 + HOUR + Duration::from_mins(5));
    }

    #[test]
    fn concurrent_ticks_are_single_flight() {
        let clock = FixedClock::new(T0);
        let r = reloader(&clock, [Ok(material("a", T0))]);
        let (first, second) = block_on(zip(r.tick(), r.tick()));
        assert!(matches!(first, ReloadOutcome::Swapped { generation: 1 }));
        assert!(matches!(second, ReloadOutcome::Unchanged));
        assert_eq!(r.loader.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn material_older_than_hard_expiry_is_expired_on_first_tick() {
        let clock = FixedClock::new(T0 + 25 * HOUR);
        let r = reloader(&clock, [Ok(material("a", T0))]);
        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::Expired {
                error: ReloadError::TooOld { .. }
            }
        ));
        assert!(r.handle().snapshot().is_err());
    }

    #[test]
    fn prod_policy_is_capped() {
        let long = ReloadPolicy {
            hard_expiry: 48 * HOUR,
            ..policy()
        };
        assert!(long.validate(Tier::Prod).is_err());
        long.validate(Tier::NonProd).unwrap();
        let inverted = ReloadPolicy {
            stale_if_error: 30 * HOUR,
            ..policy()
        };
        assert!(inverted.validate(Tier::NonProd).is_err());
        ReloadPolicy::default().validate(Tier::Prod).unwrap();
    }

    /// TSLSIG-055, GS-A_4899: at most a day between checks, in every tier.
    #[test]
    fn tslsig_055_the_interval_is_at_most_a_day() {
        let daily = ReloadPolicy {
            interval: MAX_RELOAD_INTERVAL,
            ..policy()
        };
        daily.validate(Tier::Prod).unwrap();
        let longer = ReloadPolicy {
            interval: MAX_RELOAD_INTERVAL + Duration::from_secs(1),
            ..policy()
        };
        assert!(longer.validate(Tier::NonProd).is_err());
    }

    /// The production roots.json with a published TSL, as loaded at `fetched_at`.
    #[cfg(feature = "brainpool")]
    fn published(fetched_at: Timestamp) -> TrustMaterial {
        let read = |suffix: &str| {
            std::fs::read(format!(
                "{}/../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let meta = |etag: &str| Meta {
            etag: Some(etag.to_owned()),
            last_modified: None,
            fetched_at,
            max_age: None,
            source: Source::Http,
        };
        TrustMaterial::new(
            crate::roots::ROOTS_PROD.to_vec(),
            meta("roots"),
            read("xml"),
            meta("tsl"),
        )
        .with_detached(Some(Detached {
            signature: read("sig"),
            signature_meta: meta("sig"),
            signer_status: None,
        }))
    }

    #[cfg(feature = "brainpool")]
    fn production(
        clock: &FixedClock,
        script: impl IntoIterator<Item = Result<TrustMaterial, LoadError>>,
    ) -> Reloader<VecLoader, impl Fn() -> Timestamp + '_> {
        Reloader::new(
            TrustConfig::preset_prod(),
            Tier::Prod,
            VecLoader::new(script),
            move || clock.now(),
            policy(),
        )
        .unwrap()
    }

    #[cfg(feature = "brainpool")]
    fn codes(status: &ReloadStatus) -> Vec<crate::tsl_signature::TslCode> {
        status.tsl_warnings.iter().map(|w| w.code).collect()
    }

    #[cfg(feature = "brainpool")]
    fn verify_code(outcome: &ReloadOutcome) -> Option<crate::tsl_signature::TslCode> {
        match outcome {
            ReloadOutcome::Expired {
                error: ReloadError::Verify(e),
            }
            | ReloadOutcome::KeptStale {
                error: ReloadError::Verify(e),
                ..
            } => e.tsl.as_ref().map(|t| t.code),
            _ => None,
        }
    }

    /// 2026-10-03T00:00:00Z.
    #[cfg(feature = "brainpool")]
    const OCT_3: Timestamp = Timestamp(1_790_985_600);

    /// TSLSIG-051, TSLSIG-053, TSLSIG-043: a verified list replaces the CAs, the same one
    /// under new validators changes nothing. An older one is rejected by the next test.
    #[cfg(feature = "brainpool")]
    #[test]
    fn tslsig_051_the_tsl_is_verified_and_follows_its_sequence() {
        use crate::tsl_signature::TslCode;
        let clock = FixedClock::new(OCT_3);
        let r = production(
            &clock,
            [
                Ok(published(OCT_3)),
                Ok(TrustMaterial {
                    meta: [
                        published(OCT_3).meta[0].clone(),
                        Meta {
                            etag: Some("revalidated".into()),
                            ..published(OCT_3).meta[1].clone()
                        },
                    ],
                    ..published(OCT_3)
                }),
            ],
        )
        .with_stored_tsl(TslState {
            id: "ID31033420260927230007Z".into(),
            sequence_number: 10334,
        });
        assert!(matches!(
            block_on(r.tick()),
            ReloadOutcome::Swapped { generation: 1 }
        ));
        let status = r.handle().status();
        assert_eq!(
            status.tsl_state.as_ref().map(|s| s.sequence_number),
            Some(10337)
        );
        assert_eq!(codes(&status), [TslCode::NoOcspCheck]);
        assert_eq!(r.handle().snapshot().unwrap().intermediates().len(), 71);

        assert!(matches!(block_on(r.tick()), ReloadOutcome::Unchanged));
        assert_eq!(r.handle().status().generation, 1);
    }

    /// TSLSIG-053 across a restart: the persisted state rejects an older list at once.
    #[cfg(feature = "brainpool")]
    #[test]
    fn tslsig_053_a_stored_state_survives_a_restart() {
        let clock = FixedClock::new(OCT_3);
        let stored = TslState {
            id: "ID31033820261127000007Z".into(),
            sequence_number: 10338,
        };
        let r = production(&clock, [Ok(published(OCT_3)), Ok(published(OCT_3))])
            .with_stored_tsl(stored.clone());
        assert_eq!(r.handle().status().tsl_state, Some(stored));
        let outcome = block_on(r.tick());
        assert!(
            matches!(outcome, ReloadOutcome::Expired { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            verify_code(&outcome),
            Some(crate::tsl_signature::TslCode::TslIdIncorrect)
        );
    }

    /// TSLSIG-054: a list past its NextUpdate, without grace period, is not used.
    #[cfg(feature = "brainpool")]
    #[test]
    fn tslsig_054_an_overdue_tsl_is_not_used() {
        let after = Timestamp::parse_rfc3339("2026-12-01T00:00:00Z").unwrap();
        let clock = FixedClock::new(after);
        let r = production(&clock, [Ok(published(after)), Ok(published(after))]);
        let outcome = block_on(r.tick());
        assert_eq!(
            verify_code(&outcome),
            Some(crate::tsl_signature::TslCode::ValidityWarning2)
        );
        assert!(r.handle().snapshot().is_err());
    }

    /// TSLSIG-054: a reload that only confirms unchanged material verifies nothing, so the
    /// same list, supplied again past its NextUpdate, must not stay in use.
    #[cfg(feature = "brainpool")]
    #[test]
    fn tslsig_054_an_unchanged_tsl_stops_being_used_at_its_next_update() {
        let clock = FixedClock::new(OCT_3);
        let after = Timestamp::parse_rfc3339("2026-12-01T00:00:00Z").unwrap();
        let r = production(&clock, [Ok(published(OCT_3)), Ok(published(after))]);
        assert!(matches!(block_on(r.tick()), ReloadOutcome::Swapped { .. }));
        assert!(r.handle().snapshot().is_ok());
        clock.set(after);
        assert!(matches!(block_on(r.tick()), ReloadOutcome::Unchanged));
        assert!(r.handle().snapshot().is_err());
        assert_eq!(r.handle().status().state, State::Expired);
    }

    /// Answers every signer status check with one scripted status.
    #[cfg(feature = "brainpool")]
    struct SignerStatus(crate::revocation::RevocationStatus);

    #[cfg(feature = "brainpool")]
    impl RevocationChecker for SignerStatus {
        async fn check(
            &self,
            _: &crate::Certificate,
            _: &crate::Certificate,
            _: &TrustStore,
        ) -> Result<crate::revocation::RevocationResult, crate::error::ValidationError> {
            let mut result = crate::revocation::RevocationResult::unknown(OCT_3, "");
            result.status = self.0;
            Ok(result)
        }
    }

    /// TSLSIG-040, TSLSIG-041: with a checker, the signer's status decides.
    #[cfg(feature = "brainpool")]
    #[test]
    fn tslsig_040_the_signer_status_decides() {
        use crate::revocation::RevocationStatus;
        let clock = FixedClock::new(OCT_3);
        let good = production(&clock, [Ok(published(OCT_3))])
            .with_signer_status(SignerStatus(RevocationStatus::Good));
        assert!(matches!(
            block_on(good.tick()),
            ReloadOutcome::Swapped { .. }
        ));
        assert!(
            good.handle().status().tsl_warnings.is_empty(),
            "{:?}",
            good.handle().status().tsl_warnings
        );

        let revoked = production(&clock, [Ok(published(OCT_3))])
            .with_signer_status(SignerStatus(RevocationStatus::Revoked));
        let outcome = block_on(revoked.tick());
        assert_eq!(
            verify_code(&outcome),
            Some(crate::tsl_signature::TslCode::CertRevoked)
        );
        assert!(revoked.handle().snapshot().is_err());
    }
}
