//! Time as an injected dependency. Validity checks and the loading layer read the time
//! only through [`Clock`], so tests drive it with a fixed clock and wasm32 builds need no
//! system time.

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

impl core::fmt::Display for Timestamp {
    /// RFC 3339 in UTC, e.g. `2025-12-31T23:59:59Z`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let days = self.0 / 86_400;
        let secs = self.0 % 86_400;
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }
}

/// Proleptic Gregorian date of the day `days` after 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, restricted to non-negative days).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_rfc3339_utc() {
        assert_eq!(Timestamp(0).to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(Timestamp(1_767_225_599).to_string(), "2025-12-31T23:59:59Z");
        assert_eq!(Timestamp(951_782_400).to_string(), "2000-02-29T00:00:00Z");
        assert_eq!(Timestamp(4_102_444_800).to_string(), "2100-01-01T00:00:00Z");
    }
}
