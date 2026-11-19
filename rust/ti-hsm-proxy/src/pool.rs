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

use std::num::NonZeroUsize;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use cryptoki::types::AuthPin;

use crate::pkcs11::{Error, Module, Token};

/// A fixed number of logged-in sessions on one token, lent to one caller at a time.
///
/// A PKCS#11 session runs one operation at a time, so the sessions are what bounds how many
/// operations the token sees at once; their number is what the token's limits and licence
/// allow, not what the callers want. A caller that finds none free within its wait is
/// refused with [`Error::Busy`], so that a slow token makes callers fail rather than queue
/// without bound.
///
/// A key found through one session is used through any other: PKCS#11 gives a token object
/// the same handle in every session of the application.
pub struct Pool {
    idle: Mutex<Vec<Token>>,
    returned: Condvar,
    size: usize,
}

impl Module {
    /// Opens `size` sessions on the token `label` and logs in as its user.
    ///
    /// # Errors
    ///
    /// As [`Module::open`], for any of the sessions.
    pub fn pool(&self, label: &str, user_pin: &AuthPin, size: NonZeroUsize) -> Result<Pool, Error> {
        let mut idle = Vec::with_capacity(size.get());
        for _ in 0..size.get() {
            idle.push(self.open(label, user_pin)?);
        }
        Ok(Pool {
            idle: Mutex::new(idle),
            returned: Condvar::new(),
            size: size.get(),
        })
    }
}

impl Pool {
    /// How many sessions the pool holds.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Runs `operation` on a free session, waiting at most `wait` for one.
    ///
    /// A session is not given back if `operation` panics; the pool then has one fewer.
    ///
    /// # Errors
    ///
    /// [`Error::Busy`] if no session became free within `wait`, or what `operation` returns.
    pub fn with<T>(
        &self,
        wait: Duration,
        operation: impl FnOnce(&Token) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let token = self.take(wait)?;
        let result = operation(&token);
        self.lock().push(token);
        self.returned.notify_one();
        result
    }

    fn take(&self, wait: Duration) -> Result<Token, Error> {
        let deadline = Instant::now() + wait;
        let mut idle = self.lock();
        loop {
            if let Some(token) = idle.pop() {
                return Ok(token);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Busy(wait));
            }
            idle = self
                .returned
                .wait_timeout(idle, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    // The lock is held only to push or pop, which do not panic; a poisoned lock still
    // guards a whole list.
    fn lock(&self) -> MutexGuard<'_, Vec<Token>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
