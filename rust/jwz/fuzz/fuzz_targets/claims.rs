/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik, find details in the "Readme" file.
 */

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
