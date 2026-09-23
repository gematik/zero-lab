//! Time as an injected dependency. The loading layer reads the time only through
//! [`Clock`], so tests drive it with a fixed clock and wasm32 builds need no system time.

use core::ops::{Add, Sub};
use core::time::Duration;

/// Seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Time elapsed from `earlier` to `self`; zero if `earlier` is later.
    pub const fn since(self, earlier: Timestamp) -> Duration {
        Duration::from_secs(self.0.saturating_sub(earlier.0))
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Timestamp {
        Timestamp(self.0.saturating_add(rhs.as_secs()))
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Timestamp {
        Timestamp(self.0.saturating_sub(rhs.as_secs()))
    }
}

/// A source of the current time.
pub trait Clock {
    /// The current time.
    fn now(&self) -> Timestamp;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

impl<C: Clock + ?Sized> Clock for std::sync::Arc<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

/// The operating system's wall clock.
#[cfg(feature = "os")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "os")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp(since_epoch.as_secs())
    }
}

/// A clock that only moves when told to; for tests. Share it through `&FixedClock` or
/// `Arc<FixedClock>` so the test can advance time under the code it drives.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub struct FixedClock(std::sync::atomic::AtomicU64);

#[cfg(any(test, feature = "test-util"))]
impl FixedClock {
    /// A clock standing at `now`.
    pub fn new(now: Timestamp) -> Self {
        FixedClock(std::sync::atomic::AtomicU64::new(now.0))
    }

    /// Moves the clock to `now`.
    pub fn set(&self, now: Timestamp) {
        self.0.store(now.0, std::sync::atomic::Ordering::SeqCst);
    }

    /// Moves the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        self.0
            .fetch_add(by.as_secs(), std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
