/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
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
