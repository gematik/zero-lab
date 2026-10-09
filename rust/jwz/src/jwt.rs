//! JSON Web Token claims (RFC 7519): [`Claims`] parsed from the payload of a verified
//! JWS or a decrypted JWE, and checked against a [`ClaimsPolicy`] with a [`Clock`].
//!
//! This module never sees a token, only a payload: the type-state of [`jws`](crate::jws)
//! and [`jwe`](crate::jwe) makes the payload available only after verification or
//! decryption, so claims cannot be read from an unverified token through jwz.
//!
//! ```
//! use jwz::jwt::{Claims, FixedClock};
//! use jwz::profile::Profile;
//!
//! let claims = Claims::parse(br#"{"iss":"https://idp","exp":1000}"#)?;
//! claims.validate(&Profile::strict().claims, &FixedClock(900))?;
//! assert_eq!(claims.iss(), Some("https://idp"));
//! # Ok::<(), jwz::Error>(())
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use serde_json::{Map, Value};

use crate::error::{Error, ErrorCode};
use crate::json;
use crate::profile::ClaimsPolicy;

/// The current time, in seconds since the Unix epoch. The only way time enters jwz, so
/// a test can fix it.
pub trait Clock {
    /// Seconds since 1970-01-01T00:00:00Z.
    fn now(&self) -> u64;
}

/// The system clock.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }
}

/// A clock that always says the same time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

/// The claims of a JWT: a JSON object, duplicate members refused.
#[derive(Clone, Debug, PartialEq)]
pub struct Claims {
    members: Map<String, Value>,
}

impl Claims {
    /// The claims set in `payload` (RFC 7519 §7.2 step 10).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Json`] or [`ErrorCode::DuplicateMember`].
    pub fn parse(payload: &[u8]) -> Result<Claims, Error> {
        Ok(Claims {
            members: json::parse_object(payload, "claims")?,
        })
    }

    /// Every claim.
    pub fn members(&self) -> &Map<String, Value> {
        &self.members
    }

    /// The claim `name`.
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.members.get(name)
    }

    /// `iss`, if it is a string.
    pub fn iss(&self) -> Option<&str> {
        self.str("iss")
    }

    /// `sub`, if it is a string.
    pub fn sub(&self) -> Option<&str> {
        self.str("sub")
    }

    /// `jti`, if it is a string.
    pub fn jti(&self) -> Option<&str> {
        self.str("jti")
    }

    /// `aud`: RFC 7519 §4.1.3 allows one string or an array of strings.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidClaim`] for any other form.
    pub fn aud(&self) -> Result<Vec<&str>, Error> {
        let invalid = Error::new(ErrorCode::InvalidClaim, "aud");
        match self.members.get("aud") {
            None => Ok(Vec::new()),
            Some(Value::String(one)) => Ok(alloc::vec![one.as_str()]),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().ok_or(invalid))
                .collect(),
            Some(_) => Err(invalid),
        }
    }

    /// `exp`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidClaim`] if it is not a NumericDate.
    pub fn exp(&self) -> Result<Option<u64>, Error> {
        self.numeric_date("exp")
    }

    /// `nbf`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidClaim`] if it is not a NumericDate.
    pub fn nbf(&self) -> Result<Option<u64>, Error> {
        self.numeric_date("nbf")
    }

    /// `iat`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidClaim`] if it is not a NumericDate.
    pub fn iat(&self) -> Result<Option<u64>, Error> {
        self.numeric_date("iat")
    }

    fn str(&self, name: &str) -> Option<&str> {
        self.members.get(name).and_then(Value::as_str)
    }

    /// RFC 7519 §2: a NumericDate is a JSON number of seconds since the epoch, possibly
    /// non-integer; jwz rounds a fraction down and refuses negative values.
    fn numeric_date(&self, name: &'static str) -> Result<Option<u64>, Error> {
        let Some(value) = self.members.get(name) else {
            return Ok(None);
        };
        let invalid = Error::new(ErrorCode::InvalidClaim, name);
        if let Some(seconds) = value.as_u64() {
            return Ok(Some(seconds));
        }
        let seconds = value
            .as_f64()
            .filter(|s| s.is_finite() && *s >= 0.0 && *s < 18_446_744_073_709_551_616.0)
            .ok_or(invalid)?;
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "finite, non-negative and below 2^64, checked above"
        )]
        Ok(Some(seconds as u64))
    }

    /// Checks the claims against `policy` at `clock`'s time (RFC 7519 §4.1, §7.2).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::MissingMember`] for a required claim that is absent,
    /// [`ErrorCode::Expired`] past `exp` or `max_age`, [`ErrorCode::NotYetValid`] before
    /// `nbf` or `iat`, [`ErrorCode::InvalidClaim`] for a claim of the wrong type or an
    /// issuer or audience the policy does not accept.
    pub fn validate(&self, policy: &ClaimsPolicy, clock: &dyn Clock) -> Result<(), Error> {
        let now = clock.now();
        let leeway = policy.leeway;
        // RFC 7519 §4.1.1, §4.1.2, §4.1.7: StringOrURI / string claims.
        for name in ["iss", "sub", "jti"] {
            if self.members.get(name).is_some_and(|v| !v.is_string()) {
                return Err(Error::new(ErrorCode::InvalidClaim, "string claim"));
            }
        }
        // RFC 7519 §4.1.4: the current time MUST be before exp.
        match self.exp()? {
            Some(exp) if now >= exp.saturating_add(leeway) => {
                return Err(Error::new(ErrorCode::Expired, "exp"));
            }
            None if policy.require_exp => {
                return Err(Error::new(ErrorCode::MissingMember, "exp"));
            }
            _ => {}
        }
        // RFC 7519 §4.1.5: the current time MUST be after or equal to nbf.
        if let Some(nbf) = self.nbf()?
            && now.saturating_add(leeway) < nbf
        {
            return Err(Error::new(ErrorCode::NotYetValid, "nbf"));
        }
        let iat = self.iat()?;
        if let Some(iat) = iat
            && now.saturating_add(leeway) < iat
        {
            return Err(Error::new(ErrorCode::NotYetValid, "iat"));
        }
        if let Some(max_age) = policy.max_age {
            let iat = iat.ok_or(Error::new(ErrorCode::MissingMember, "iat"))?;
            if now > iat.saturating_add(max_age).saturating_add(leeway) {
                return Err(Error::new(ErrorCode::Expired, "iat"));
            }
        }
        // RFC 7519 §4.1.1: iss is compared as a case-sensitive string.
        if let Some(issuer) = &policy.issuer
            && self.iss() != Some(issuer.as_str())
        {
            return Err(Error::new(ErrorCode::InvalidClaim, "iss"));
        }
        // RFC 7519 §4.1.3: the recipient MUST identify itself with a value in aud.
        let aud = self.aud()?;
        if let Some(audience) = &policy.audience
            && !aud.contains(&audience.as_str())
        {
            return Err(Error::new(ErrorCode::InvalidClaim, "aud"));
        }
        if policy
            .required
            .iter()
            .any(|name| !self.members.contains_key(name))
        {
            return Err(Error::new(ErrorCode::MissingMember, "required claim"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    fn check(claims: &str, policy: &ClaimsPolicy, now: u64) -> Result<(), ErrorCode> {
        Claims::parse(claims.as_bytes())
            .and_then(|c| c.validate(policy, &FixedClock(now)))
            .map_err(|e| e.code())
    }

    #[test]
    fn rfc_7519_4_1_4_exp_with_leeway() {
        let policy = Profile::strict().claims;
        assert_eq!(check(r#"{"exp":1000}"#, &policy, 1059), Ok(()));
        assert_eq!(
            check(r#"{"exp":1000}"#, &policy, 1060),
            Err(ErrorCode::Expired)
        );
        assert_eq!(check(r#"{"exp":1000.9}"#, &policy, 1059), Ok(()));
        assert_eq!(check("{}", &policy, 0), Err(ErrorCode::MissingMember));
        for bad in [r#"{"exp":"1000"}"#, r#"{"exp":-1}"#, r#"{"exp":null}"#] {
            assert_eq!(
                check(bad, &policy, 0),
                Err(ErrorCode::InvalidClaim),
                "{bad}"
            );
        }
    }

    #[test]
    fn rfc_7519_4_1_5_nbf_and_iat() {
        let mut policy = Profile::strict().claims;
        policy.require_exp = false;
        assert_eq!(check(r#"{"nbf":1060}"#, &policy, 1000), Ok(()));
        assert_eq!(
            check(r#"{"nbf":1061}"#, &policy, 1000),
            Err(ErrorCode::NotYetValid)
        );
        assert_eq!(
            check(r#"{"iat":1061}"#, &policy, 1000),
            Err(ErrorCode::NotYetValid)
        );
        policy.max_age = Some(300);
        assert_eq!(check(r#"{"iat":1000}"#, &policy, 1360), Ok(()));
        assert_eq!(
            check(r#"{"iat":1000}"#, &policy, 1361),
            Err(ErrorCode::Expired)
        );
        assert_eq!(check("{}", &policy, 0), Err(ErrorCode::MissingMember));
    }

    #[test]
    fn rfc_7519_4_1_1_and_4_1_3_issuer_and_audience() {
        let mut policy = Profile::strict().claims;
        policy.require_exp = false;
        policy.issuer = Some("https://idp".into());
        policy.audience = Some("client".into());
        assert_eq!(
            check(r#"{"iss":"https://idp","aud":"client"}"#, &policy, 0),
            Ok(())
        );
        assert_eq!(
            check(r#"{"iss":"https://idp","aud":["x","client"]}"#, &policy, 0),
            Ok(())
        );
        for (bad, code) in [
            (
                r#"{"iss":"https://IDP","aud":"client"}"#,
                ErrorCode::InvalidClaim,
            ),
            (
                r#"{"iss":"https://idp","aud":"other"}"#,
                ErrorCode::InvalidClaim,
            ),
            (r#"{"iss":"https://idp"}"#, ErrorCode::InvalidClaim),
            (
                r#"{"iss":"https://idp","aud":[1]}"#,
                ErrorCode::InvalidClaim,
            ),
            (r#"{"iss":1,"aud":"client"}"#, ErrorCode::InvalidClaim),
            (
                r#"{"iss":"a","iss":"https://idp"}"#,
                ErrorCode::DuplicateMember,
            ),
        ] {
            assert_eq!(check(bad, &policy, 0), Err(code), "{bad}");
        }
        policy.issuer = None;
        policy.audience = None;
        policy.required = alloc::vec!["sub".into()];
        assert_eq!(check(r#"{"sub":"x"}"#, &policy, 0), Ok(()));
        assert_eq!(check("{}", &policy, 0), Err(ErrorCode::MissingMember));
    }
}
