//! Hot reload: [`Reloader`] loads, verifies and swaps trust material; everything else
//! reads the current [`TrustStore`] through [`TrustStoreHandle::snapshot`].

use core::time::Duration;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::ArcSwapOption;

use super::artifact::{Artifact, Source, TrustMaterial};
use super::clock::{Clock, Timestamp};
use super::loader::{LoadError, Loader};
use super::maybe_send::{MaybeSend, MaybeSync};
use super::verify::{VerifyError, VerifyFn, verify_material};
use crate::{Error, Tier, TrustConfig, TrustStore};

/// The longest a production deployment may keep using trust material it could not
/// refresh. Past it, the TSL may list CAs that have since been withdrawn.
pub const MAX_PROD_HARD_EXPIRY: Duration = Duration::from_hours(24);

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
    /// [`Error::InconsistentConfig`] if the interval is zero, `stale_if_error` exceeds
    /// `hard_expiry`, or, under [`Tier::Prod`], `hard_expiry` exceeds
    /// [`MAX_PROD_HARD_EXPIRY`].
    pub fn validate(&self, tier: Tier) -> Result<(), Error> {
        let inconsistent = |reason| Err(Error::InconsistentConfig { reason });
        if self.interval.is_zero() {
            return inconsistent("reload interval must not be zero");
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
    etags: [Option<String>; 2],
    fetched_at: Timestamp,
    tsl_next_update: Option<Timestamp>,
    source: Source,
    generation: u64,
}

#[derive(Debug, Default)]
struct Attempts {
    attempted_at: Option<Timestamp>,
    error: Option<(Timestamp, String)>,
    succeeded: bool,
}

/// Shared read access to the current trust store.
#[derive(Debug)]
pub struct TrustStoreHandle<C> {
    current: ArcSwapOption<Current>,
    attempts: Mutex<Attempts>,
    clock: C,
    stale_if_error: Duration,
    hard_expiry: Duration,
}

impl<C: Clock> TrustStoreHandle<C> {
    /// The current trust store; cheap, call it per request.
    ///
    /// # Errors
    ///
    /// [`Expired`] before the first successful load and once the material is older
    /// than `hard_expiry`, even if no reload has run since.
    pub fn snapshot(&self) -> Result<Arc<TrustStore>, Expired> {
        let current = self
            .current
            .load_full()
            .ok_or(Expired { fetched_at: None })?;
        if self.clock.now().since(current.fetched_at) >= self.hard_expiry {
            return Err(Expired {
                fetched_at: Some(current.fetched_at),
            });
        }
        Ok(Arc::clone(&current.store))
    }

    /// The current [`ReloadStatus`].
    pub fn status(&self) -> ReloadStatus {
        let now = self.clock.now();
        let current = self.current.load_full();
        let attempts = self.attempts();
        let staleness = current
            .as_ref()
            .map_or(Duration::ZERO, |c| now.since(c.fetched_at));
        let state = match &current {
            None => State::Uninitialised,
            Some(_) if staleness >= self.hard_expiry => State::Expired,
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
        }
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
/// uses (see the `tokio` feature for a ready-made driver).
pub struct Reloader<L, C> {
    config: TrustConfig,
    loader: L,
    handle: TrustStoreHandle<C>,
    policy: ReloadPolicy,
    jitter_seed: RandomState,
    in_flight: AtomicBool,
    verify: VerifyFn,
}

impl<L, C> core::fmt::Debug for Reloader<L, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reloader")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<L, C> Reloader<L, C>
where
    L: Loader + MaybeSend + MaybeSync,
    C: Clock + MaybeSend + MaybeSync,
{
    /// A reloader for `config` in `tier`. Nothing is loaded until the first
    /// [`tick`](Self::tick).
    ///
    /// # Errors
    ///
    /// [`Error::InconsistentConfig`] or [`Error::Der`] if `config` or `policy` fail
    /// validation for `tier`.
    pub fn new(
        config: TrustConfig,
        tier: Tier,
        loader: L,
        clock: C,
        policy: ReloadPolicy,
    ) -> Result<Self, Error> {
        config.validate(tier)?;
        policy.validate(tier)?;
        Ok(Reloader {
            config,
            loader,
            handle: TrustStoreHandle {
                current: ArcSwapOption::empty(),
                attempts: Mutex::default(),
                clock,
                stale_if_error: policy.stale_if_error,
                hard_expiry: policy.hard_expiry,
            },
            policy,
            jitter_seed: RandomState::new(),
            in_flight: AtomicBool::new(false),
            verify: verify_material,
        })
    }

    /// Read access for request handlers.
    pub fn handle(&self) -> &TrustStoreHandle<C> {
        &self.handle
    }

    /// When the next tick is due: the last attempt plus interval and this process's
    /// jitter, or earlier if the TSL's `NextUpdate` (less the lead) comes first. Now,
    /// if nothing was attempted yet.
    pub fn next_due(&self) -> Timestamp {
        let Some(last) = self.handle.attempts().attempted_at else {
            return self.handle.clock.now();
        };
        let periodic = last + self.policy.interval + self.jitter(last);
        let deadline = self
            .handle
            .current
            .load()
            .as_ref()
            .and_then(|c| c.tsl_next_update)
            .filter(|_| self.policy.honor_tsl_next_update)
            .map(|next_update| next_update - self.policy.next_update_lead);
        deadline.map_or(periodic, |d| d.min(periodic))
    }

    /// Time left until the next tick is due; zero if it is due already.
    pub fn until_due(&self) -> Duration {
        self.next_due().since(self.handle.clock.now())
    }

    /// Whether a tick is due now.
    pub fn due(&self) -> bool {
        self.handle.clock.now() >= self.next_due()
    }

    /// One reload attempt. Single-flight: a tick that starts while another is running
    /// returns [`ReloadOutcome::Unchanged`] at once. Always records the attempt in the
    /// status. Until the roots walk and TSL signature check are ported from `gempki`,
    /// verifying changed material panics.
    pub async fn tick(&self) -> ReloadOutcome {
        if self.in_flight.swap(true, Ordering::AcqRel) {
            return ReloadOutcome::Unchanged;
        }
        let _in_flight = InFlight(&self.in_flight);

        let loaded = self.loader.load_all().await;
        let now = self.handle.clock.now();
        self.handle.attempts().attempted_at = Some(now);

        let material = match loaded {
            Ok(material) => material,
            Err(error) => return self.fail(now, error.into()),
        };
        let age = now.since(material.fetched_at);
        if age >= self.policy.hard_expiry {
            return self.fail(now, ReloadError::TooOld { age });
        }
        if let Some(current) = self.handle.current.load_full()
            && same_etags(&current.etags, &material)
        {
            self.handle.current.store(Some(Arc::new(Current {
                store: Arc::clone(&current.store),
                etags: current.etags.clone(),
                fetched_at: current.fetched_at.max(material.fetched_at),
                tsl_next_update: current.tsl_next_update,
                source: current.source,
                generation: current.generation,
            })));
            self.handle.attempts().succeeded = true;
            return ReloadOutcome::Unchanged;
        }
        match (self.verify)(&self.config, &material) {
            Ok(verified) => self.swap(&material, verified),
            Err(error) => self.fail(now, error.into()),
        }
    }

    fn swap(&self, material: &TrustMaterial, verified: super::Verified) -> ReloadOutcome {
        let generation = self
            .handle
            .current
            .load()
            .as_ref()
            .map_or(0, |c| c.generation)
            + 1;
        let tsl_meta = material.meta(Artifact::Tsl);
        self.handle.current.store(Some(Arc::new(Current {
            tsl_next_update: verified.tsl_next_update,
            store: Arc::new(TrustStore::from_verified(verified)),
            etags: [material.meta[0].etag.clone(), material.meta[1].etag.clone()],
            fetched_at: material.fetched_at,
            source: tsl_meta.source,
            generation,
        })));
        self.handle.attempts().succeeded = true;
        ReloadOutcome::Swapped { generation }
    }

    fn fail(&self, now: Timestamp, error: ReloadError) -> ReloadOutcome {
        {
            let mut attempts = self.handle.attempts();
            attempts.succeeded = false;
            attempts.error = Some((now, error.to_string()));
        }
        let Some(current) = self.handle.current.load_full() else {
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

fn same_etags(current: &[Option<String>; 2], material: &TrustMaterial) -> bool {
    current
        .iter()
        .zip(&material.meta)
        .all(|(old, new)| old.is_some() && *old == new.etag)
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
    fn test_verify(_: &TrustConfig, m: &TrustMaterial) -> Result<Verified, VerifyError> {
        if m.roots == b"tampered" {
            return Err(VerifyError {
                reason: "roots do not chain to the anchor".into(),
            });
        }
        let tsl_next_update = std::str::from_utf8(&m.tsl)
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Timestamp);
        Ok(Verified {
            roots: Vec::new(),
            tsl_next_update,
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
    ) -> Reloader<VecLoader, &FixedClock> {
        Reloader::new(
            TrustConfig::preset_prod(),
            Tier::Prod,
            VecLoader::new(script),
            clock,
            policy(),
        )
        .unwrap()
        .with_verifier(test_verify)
    }

    fn offline() -> LoadError {
        LoadError::Offline(Artifact::Tsl)
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
            TrustConfig::preset_prod(),
            Tier::Prod,
            VecLoader::new([Ok(material("a", T0))]),
            &clock,
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
}
