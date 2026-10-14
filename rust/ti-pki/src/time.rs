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

//! Time for ti-pki: [`Clock`] and [`Timestamp`] live in `ti-types`, so every TI crate
//! shares them; [`FixedClock`] drives tests.

#[cfg(any(test, feature = "test-util"))]
use core::time::Duration;

#[cfg(all(
    feature = "os",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
pub use ti_types::time::SystemClock;
pub use ti_types::time::{Clock, Timestamp};

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
