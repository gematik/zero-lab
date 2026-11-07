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

//! The time as jwz reads it. jwz validates claims against its own `Clock` trait and takes
//! no function yet, so this adapter hands it the caller's `impl Fn() -> Timestamp`; once
//! jwz accepts a function as its clock, the adapter can go.

use jwz::jwt::Clock;
use ti_types::Timestamp;

/// `now` as a jwz [`Clock`]: every read calls the function again.
pub(crate) struct Now<'a, N>(pub(crate) &'a N);

impl<N: Fn() -> Timestamp> Clock for Now<'_, N> {
    fn now(&self) -> u64 {
        (self.0)().0
    }
}
