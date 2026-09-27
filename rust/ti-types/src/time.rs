//! Time as an injected dependency. TI libraries read the time only through [`Clock`], so
//! tests drive it with a fixed clock and wasm32 builds need no system time.

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

impl Timestamp {
    /// Parses an RFC 3339 / XML Schema `dateTime` with a time zone, e.g.
    /// `2026-10-13T23:00:08Z` or `2026-10-14T01:00:08.5+02:00`; fractions of a second
    /// are dropped. `None` for anything else, including instants before 1970.
    pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
        let b = s.as_bytes();
        let num = |range: core::ops::Range<usize>| -> Option<u64> {
            let digits = b.get(range)?;
            digits
                .iter()
                .all(u8::is_ascii_digit)
                .then(|| digits.iter().fold(0, |n, d| n * 10 + u64::from(d - b'0')))
        };
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') {
            return None;
        }
        if b[13] != b':' || b[16] != b':' {
            return None;
        }
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        let mut rest = &s[19..];
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return None;
            }
            rest = &fraction[digits..];
        }
        let offset: i64 = match rest.as_bytes() {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
                let hm = [h1, h2, m1, m2];
                if !hm.iter().all(|d| d.is_ascii_digit()) {
                    return None;
                }
                let value = |d: &u8| i64::from(d - b'0');
                let minutes = (value(h1) * 10 + value(h2)) * 60 + value(m1) * 10 + value(m2);
                if *sign == b'+' {
                    minutes * 60
                } else {
                    -minutes * 60
                }
            }
            _ => return None,
        };
        let days = days_from_civil(year, month, day)?;
        let local = i64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()?;
        u64::try_from(local - offset).ok().map(Timestamp)
    }
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the given date (Howard Hinnant's `days_from_civil`), `None`
/// before 1970.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
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

impl<C: Clock + ?Sized> Clock for alloc::sync::Arc<C> {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

/// The operating system's wall clock.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Timestamp(since_epoch.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString as _;

    use super::*;

    #[test]
    fn display_is_rfc3339_utc() {
        assert_eq!(Timestamp(0).to_string(), "1970-01-01T00:00:00Z");
        assert_eq!(Timestamp(1_767_225_599).to_string(), "2025-12-31T23:59:59Z");
        assert_eq!(Timestamp(951_782_400).to_string(), "2000-02-29T00:00:00Z");
        assert_eq!(Timestamp(4_102_444_800).to_string(), "2100-01-01T00:00:00Z");
    }

    #[test]
    fn parse_is_the_inverse_of_display() {
        for t in [0, 951_782_400, 1_767_225_599, 1_789_340_408, 4_102_444_800] {
            let ts = Timestamp(t);
            assert_eq!(Timestamp::parse_rfc3339(&ts.to_string()), Some(ts));
        }
    }

    #[test]
    fn parse_offsets_fractions_and_garbage() {
        let utc = Timestamp::parse_rfc3339("2026-10-13T23:00:08Z").unwrap();
        assert_eq!(
            Timestamp::parse_rfc3339("2026-10-14T01:00:08.123+02:00"),
            Some(utc)
        );
        assert_eq!(
            Timestamp::parse_rfc3339("2026-10-13T20:30:08-02:30"),
            Some(utc)
        );
        for bad in [
            "",
            "2026-10-13",
            "2026-10-13T23:00:08",
            "2026-02-30T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-13T24:00:00Z",
            "2026-10-13T23:00:08.Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(Timestamp::parse_rfc3339(bad), None, "{bad:?}");
        }
    }
}
