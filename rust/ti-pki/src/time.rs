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
