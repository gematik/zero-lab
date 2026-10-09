//! Any input to JWT claims parsing and validation: errors, never panics.
#![no_main]

use jwz::jwt::{Claims, FixedClock};
use jwz::profile::Profile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], u64)| {
    let (payload, now) = input;
    if let Ok(claims) = Claims::parse(payload) {
        let mut policy = Profile::strict().claims;
        policy.max_age = Some(600);
        policy.issuer = Some("https://idp".into());
        policy.audience = Some("client".into());
        let _ = claims.validate(&policy, &FixedClock(now));
        let _ = claims.aud();
    }
});
