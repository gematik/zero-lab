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

//! Where nonces, data keys and profile ids come from.

use super::StoreError;

/// A source of cryptographically secure random bytes (STORE-040, STORE-052, STORE-061).
pub trait Random {
    /// Fills `buf`.
    ///
    /// # Errors
    ///
    /// `backend_error` if the source fails.
    fn fill(&self, buf: &mut [u8]) -> Result<(), StoreError>;
}

/// The operating system's generator (`Crypto.getRandomValues` in a browser).
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), StoreError> {
        getrandom::fill(buf).map_err(|e| StoreError::Backend(format!("random source: {e}")))
    }
}

/// Hands out given bytes in order, for reproducible records in tests and the conformance
/// adapter. Never use it for real data: every record would share its nonces.
#[cfg(feature = "test-util")]
#[derive(Debug, Default)]
pub struct FixedRandom(std::sync::Mutex<std::collections::VecDeque<u8>>);

#[cfg(feature = "test-util")]
impl FixedRandom {
    /// A source that yields `bytes`, then fails.
    pub fn new(bytes: &[u8]) -> Self {
        FixedRandom(std::sync::Mutex::new(bytes.iter().copied().collect()))
    }
}

#[cfg(feature = "test-util")]
impl Random for FixedRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), StoreError> {
        let mut q = self
            .0
            .lock()
            .map_err(|_| StoreError::Backend("fixed random poisoned".into()))?;
        if q.len() < buf.len() {
            return Err(StoreError::Backend("fixed random exhausted".into()));
        }
        for b in buf.iter_mut() {
            *b = q.pop_front().expect("length checked");
        }
        Ok(())
    }
}
