//! The trust anchors compiled into the crate, one root certificate per
//! environment: GEM.RCA8 for prod, GEM.RCA7 TEST-ONLY for dev and ref,
//! GEM.RCA8 TEST-ONLY for test, plus the TSL-Signer-CA anchor that verifies
//! the TSL's detached signature. They are taken straight from gematik's
//! distribution; if gematik rotates one, the constant changes and the crate
//! is rebuilt, there is no runtime override.

use core::fmt;
use core::str::FromStr;

use crate::Error;

/// Selects which gematik TI the crate talks to: which trust anchors, which
/// embedded roots.json and which download endpoints.
///
/// dev and ref share one set of anchors and roots, because gematik
/// distributes a single set for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Env {
    /// The production TI.
    Prod,
    /// The test environment (TEST-ONLY material).
    Test,
    /// The reference environment (TEST-ONLY material, shared with dev).
    Ref,
    /// The development environment (TEST-ONLY material, shared with ref).
    Dev,
}

impl Env {
    /// The lower-case name used on the command line and in configuration,
    /// identical to the Go implementation's `Environment` values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Env::Prod => "prod",
            Env::Test => "test",
            Env::Ref => "ref",
            Env::Dev => "dev",
        }
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Env {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "prod" => Ok(Env::Prod),
            "test" => Ok(Env::Test),
            "ref" => Ok(Env::Ref),
            "dev" => Ok(Env::Dev),
            _ => Err(Error::UnknownEnvironment(s.to_owned())),
        }
    }
}
