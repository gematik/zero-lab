//! TI environments and the production/non-production split.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

/// A TI environment. The four gematik environments plus room for more: consumers
/// match with a wildcard arm. Behavioural decisions belong on [`Tier`], never here.
///
/// Parsing accepts the canonical names and gematik's short forms (`pu`, `ru`, `tu`),
/// ignoring case; see [`Env::from_str`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum Env {
    /// Development environment.
    Dev,
    /// Test environment (Testumgebung, TU).
    #[cfg_attr(feature = "serde", serde(alias = "tu"))]
    #[cfg_attr(feature = "clap", value(alias = "tu"))]
    Test,
    /// Reference environment (Referenzumgebung, RU).
    #[cfg_attr(feature = "serde", serde(alias = "ru"))]
    #[cfg_attr(feature = "clap", value(alias = "ru"))]
    Ref,
    /// Production (Produktivumgebung, PU).
    #[cfg_attr(feature = "serde", serde(alias = "pu"))]
    #[cfg_attr(feature = "clap", value(alias = "pu"))]
    Prod,
}

/// Production or not. The only environment distinction libraries may branch on.
///
/// Deliberately exhaustive, unlike every other enum in this crate: the split is binary
/// by definition, and a wildcard arm here would hide exactly the decision a match on
/// `Tier` exists to force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// The production TI.
    Prod,
    /// Anything that is not production.
    NonProd,
}

impl Env {
    /// Whether this environment is production.
    pub const fn tier(self) -> Tier {
        match self {
            Env::Prod => Tier::Prod,
            _ => Tier::NonProd,
        }
    }

    /// Shorthand for `self.tier() == Tier::Prod`.
    pub const fn is_prod(self) -> bool {
        matches!(self.tier(), Tier::Prod)
    }

    /// Canonical lowercase name: `dev`, `test`, `ref`, `prod`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Env::Dev => "dev",
            Env::Test => "test",
            Env::Ref => "ref",
            Env::Prod => "prod",
        }
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Env {
    type Err = EnvParseError;

    /// Accepts `dev`, `test`/`tu`, `ref`/`ru` and `prod`/`pu` in any case. There is no
    /// default: anything else, including the empty string, is an error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const NAMES: [(&str, Env); 7] = [
            ("dev", Env::Dev),
            ("test", Env::Test),
            ("tu", Env::Test),
            ("ref", Env::Ref),
            ("ru", Env::Ref),
            ("prod", Env::Prod),
            ("pu", Env::Prod),
        ];
        NAMES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(s))
            .map(|&(_, env)| env)
            .ok_or_else(|| EnvParseError { input: s.into() })
    }
}

/// The input to [`Env::from_str`] named no known environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvParseError {
    /// The rejected input, verbatim.
    pub input: String,
}

impl fmt::Display for EnvParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown TI environment {:?}, expected one of dev, test (tu), ref (ru), prod (pu)",
            self.input
        )
    }
}

impl core::error::Error for EnvParseError {}

impl Tier {
    /// Canonical lowercase name: `prod`, `nonprod`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Prod => "prod",
            Tier::NonProd => "nonprod",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    const ALL: [Env; 4] = [Env::Dev, Env::Test, Env::Ref, Env::Prod];

    #[test]
    fn display_from_str_round_trip() {
        for env in ALL {
            assert_eq!(env.to_string().parse::<Env>(), Ok(env));
        }
    }

    #[test]
    fn every_alias_parses() {
        for (input, env) in [
            ("dev", Env::Dev),
            ("test", Env::Test),
            ("tu", Env::Test),
            ("ref", Env::Ref),
            ("ru", Env::Ref),
            ("prod", Env::Prod),
            ("pu", Env::Prod),
        ] {
            assert_eq!(input.parse::<Env>(), Ok(env), "{input}");
        }
    }

    #[test]
    fn parsing_ignores_case() {
        assert_eq!("PROD".parse::<Env>(), Ok(Env::Prod));
        assert_eq!("Ru".parse::<Env>(), Ok(Env::Ref));
    }

    #[test]
    fn unknown_input_is_an_error() {
        for input in ["", "staging", " prod"] {
            assert_eq!(
                input.parse::<Env>(),
                Err(EnvParseError {
                    input: input.into()
                })
            );
        }
    }

    #[test]
    fn tier_table() {
        assert_eq!(Env::Prod.tier(), Tier::Prod);
        for env in [Env::Dev, Env::Test, Env::Ref] {
            assert_eq!(env.tier(), Tier::NonProd, "{env}");
            assert!(!env.is_prod());
        }
        assert!(Env::Prod.is_prod());
    }

    #[test]
    fn tier_display() {
        assert_eq!(Tier::Prod.to_string(), "prod");
        assert_eq!(Tier::NonProd.to_string(), "nonprod");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_json_round_trip() {
        assert_eq!(serde_json::to_string(&Env::Prod).unwrap(), r#""prod""#);
        for env in ALL {
            let json = serde_json::to_string(&env).unwrap();
            assert_eq!(serde_json::from_str::<Env>(&json).unwrap(), env);
        }
        assert_eq!(serde_json::from_str::<Env>(r#""pu""#).unwrap(), Env::Prod);
    }

    #[cfg(feature = "clap")]
    #[test]
    fn clap_value_enum_parses() {
        use clap::ValueEnum;
        assert_eq!(<Env as ValueEnum>::from_str("prod", false), Ok(Env::Prod));
        assert_eq!(<Env as ValueEnum>::from_str("ru", false), Ok(Env::Ref));
        assert!(<Env as ValueEnum>::from_str("staging", false).is_err());
    }
}
