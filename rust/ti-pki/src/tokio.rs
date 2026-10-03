//! Drives a [`Reloader`] on tokio: a background task on its own thread, reload on
//! SIGHUP, and an [`AdminTrigger`] for an admin endpoint or exec probe. No web framework
//! is involved.
//!
//! The reloader runs on a dedicated thread with a current-thread runtime. The loading
//! traits deliberately carry no `Send` bounds (so they work on wasm32), which means a
//! generic tick future cannot be handed to `tokio::spawn`; on its own thread it does not
//! need to be. Everything that crosses into the application's runtime, like
//! [`AdminTrigger::trigger`], is `Send`.
//!
//! Every tick is logged with `tracing`: a verification failure at error level (possible
//! tampering), a load failure at warn while the material is `Stale` and at error from
//! `Degraded` on, a swap at info, no change at debug.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::sync::Arc;
//! use ti_pki::load::{HttpLoader, ReloadPolicy, Reloader, SystemClock};
//! use ti_pki::reqwest::ReqwestTransport;
//! use ti_pki::{Tier, TrustConfig};
//!
//! let config = TrustConfig::preset_prod();
//! let loader = HttpLoader::new(&config, ReqwestTransport::new(reqwest::Client::new()), SystemClock);
//! let reloader = Arc::new(Reloader::new(config, Tier::Prod, loader, SystemClock, ReloadPolicy::default())?);
//! let task = ti_pki::tokio::spawn_reloader(Arc::clone(&reloader))?;
//! # #[cfg(unix)]
//! ti_pki::tokio::on_sighup(task.trigger())?;
//! let outcome = task.trigger().trigger().await?; // e.g. from POST /admin/reload
//! let store = reloader.handle().snapshot()?; // per request
//! # Ok(()) }
//! ```

use std::sync::Arc;
use std::thread;

use ::tokio::sync::{mpsc, oneshot};

use crate::load::{Clock, Loader, ReloadError, ReloadOutcome, Reloader, State};
use crate::revocation::RevocationChecker;

/// A running background reloader. Dropping it stops the task; [`shutdown`](Self::shutdown)
/// also waits for the thread.
#[derive(Debug)]
pub struct ReloaderTask {
    trigger: AdminTrigger,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ReloaderTask {
    /// A trigger for on-demand reloads through this task.
    pub fn trigger(&self) -> AdminTrigger {
        self.trigger.clone()
    }

    /// Stops the task after the current tick and waits for its thread.
    ///
    /// # Errors
    ///
    /// The thread's panic payload if it panicked.
    pub fn shutdown(mut self) -> thread::Result<()> {
        self.stop.take();
        self.thread.take().map_or(Ok(()), thread::JoinHandle::join)
    }
}

impl Drop for ReloaderTask {
    fn drop(&mut self) {
        // Dropping the sender wakes the task, which then exits.
        self.stop.take();
    }
}

/// Requests an immediate reload from a running [`ReloaderTask`]. Cheap to clone; its
/// futures are `Send`, so it can live in any request handler.
#[derive(Clone, Debug)]
pub struct AdminTrigger {
    requests: mpsc::Sender<oneshot::Sender<ReloadOutcome>>,
}

/// The reloader task is no longer running.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the reloader task has stopped")]
pub struct Stopped;

impl AdminTrigger {
    /// Runs a tick now and returns its outcome. If a tick is already running, this one
    /// reports [`ReloadOutcome::Unchanged`].
    ///
    /// # Errors
    ///
    /// [`Stopped`] if the task has ended.
    pub async fn trigger(&self) -> Result<ReloadOutcome, Stopped> {
        let (reply, outcome) = oneshot::channel();
        self.requests.send(reply).await.map_err(|_| Stopped)?;
        outcome.await.map_err(|_| Stopped)
    }
}

/// Starts `reloader` on a dedicated thread: a tick whenever one is due (at once for the
/// first load), plus one per [`AdminTrigger::trigger`].
///
/// # Errors
///
/// If the runtime or the thread cannot be created.
pub fn spawn_reloader<L, C, R>(reloader: Arc<Reloader<L, C, R>>) -> std::io::Result<ReloaderTask>
where
    L: Loader + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    R: RevocationChecker + Send + Sync + 'static,
{
    let (requests, mut incoming) = mpsc::channel::<oneshot::Sender<ReloadOutcome>>(8);
    let (stop, mut stopped) = oneshot::channel::<()>();
    let runtime = ::tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let thread = thread::Builder::new()
        .name("ti-pki-reloader".into())
        .spawn(move || {
            runtime.block_on(async move {
                loop {
                    ::tokio::select! {
                        () = ::tokio::time::sleep(reloader.until_due()) => {
                            log(&reloader.tick().await);
                        }
                        Some(reply) = incoming.recv() => {
                            let outcome = reloader.tick().await;
                            log(&outcome);
                            // The requester may have given up waiting; nothing to do then.
                            let _ = reply.send(outcome);
                        }
                        _ = &mut stopped => break,
                    }
                }
            });
        })?;
    Ok(ReloaderTask {
        trigger: AdminTrigger { requests },
        stop: Some(stop),
        thread: Some(thread),
    })
}

/// Reloads whenever the process receives SIGHUP. Must be called within a tokio runtime;
/// the listener runs there until `trigger`'s task stops.
///
/// # Errors
///
/// If the signal handler cannot be installed.
#[cfg(unix)]
pub fn on_sighup(trigger: AdminTrigger) -> std::io::Result<::tokio::task::JoinHandle<()>> {
    use ::tokio::signal::unix::{SignalKind, signal};

    let mut hangups = signal(SignalKind::hangup())?;
    Ok(::tokio::spawn(async move {
        while hangups.recv().await.is_some() {
            // The reloader task logs the outcome itself.
            if trigger.trigger().await.is_err() {
                break;
            }
        }
    }))
}

fn log(outcome: &ReloadOutcome) {
    match outcome {
        ReloadOutcome::Unchanged => tracing::debug!("trust material unchanged"),
        ReloadOutcome::Swapped { generation } => {
            tracing::info!(generation, "trust material updated");
        }
        ReloadOutcome::KeptStale {
            error: error @ ReloadError::Verify(_),
            stale_for,
            ..
        } => tracing::error!(
            %error,
            stale_for_secs = stale_for.as_secs(),
            "loaded trust material failed verification, possible tampering; keeping current"
        ),
        ReloadOutcome::KeptStale {
            error,
            stale_for,
            state: State::Stale,
        } => tracing::warn!(
            %error,
            stale_for_secs = stale_for.as_secs(),
            "trust material reload failed; serving stale material"
        ),
        ReloadOutcome::KeptStale {
            error, stale_for, ..
        } => tracing::error!(
            %error,
            stale_for_secs = stale_for.as_secs(),
            "trust material reload failed; serving degraded material"
        ),
        ReloadOutcome::Expired { error } => {
            tracing::error!(%error, "trust material expired; validation unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::load::{
        Artifact, Conditional, Fetched, FixedClock, LoadError, Meta, ReloadPolicy, Source,
        Timestamp, TrustMaterial, Verified, VerifyError,
    };
    use crate::{Tier, TrustConfig};

    struct Counting(std::sync::atomic::AtomicU64);

    impl Loader for Counting {
        async fn fetch(
            &self,
            artifact: Artifact,
            _: Conditional<'_>,
        ) -> Result<Fetched, LoadError> {
            Err(LoadError::Unavailable(artifact))
        }

        async fn load_all(&self) -> Result<TrustMaterial, LoadError> {
            let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let meta = Meta {
                etag: Some(format!("v{n}")),
                last_modified: None,
                fetched_at: Timestamp(1_000),
                max_age: None,
                source: Source::Http,
            };
            Ok(TrustMaterial::new(
                Vec::new(),
                meta.clone(),
                Vec::new(),
                meta,
            ))
        }
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "must match the verifier signature"
    )]
    fn accept(
        _: &TrustConfig,
        _: &TrustMaterial,
        _: Timestamp,
        _: Option<&crate::tsl_signature::TslState>,
    ) -> Result<Verified, VerifyError> {
        Ok(Verified {
            roots: Vec::new(),
            intermediates: Vec::new(),
            tsl_next_update: None,
            tsl: None,
            sequence: crate::tsl_signature::Sequence::Newer,
        })
    }

    #[test]
    fn loads_at_start_and_on_trigger() {
        let reloader = Arc::new(
            Reloader::new(
                crate::config::tests::nist_prod_config(),
                Tier::Prod,
                Counting(0.into()),
                FixedClock::new(Timestamp(1_000)),
                ReloadPolicy {
                    interval: Duration::from_secs(3600),
                    jitter: Duration::ZERO,
                    ..ReloadPolicy::default()
                },
            )
            .unwrap()
            .with_verifier(accept),
        );
        let task = spawn_reloader(Arc::clone(&reloader)).unwrap();
        let trigger = task.trigger();
        let runtime = ::tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        // Each tick loads new etags, so every tick that runs swaps; whether the initial
        // due tick or the trigger runs first is up to select!.
        let outcome = runtime.block_on(trigger.trigger()).unwrap();
        assert!(matches!(outcome, ReloadOutcome::Swapped { .. }));
        reloader.handle().snapshot().unwrap();

        task.shutdown().unwrap();
        assert_eq!(runtime.block_on(trigger.trigger()).unwrap_err(), Stopped);
    }
}
