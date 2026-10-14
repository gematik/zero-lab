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

//! Runs ti-pki's async API without a runtime. Everything this tool plugs into it is
//! blocking (ureq, files), so each future is complete when first polled; an executor
//! would only add dependencies.

use core::pin::pin;
use core::task::{Context, Poll, Waker};

/// The output of `future`, which must not wait on anything.
///
/// # Panics
///
/// If `future` is pending after its first poll, i.e. something asynchronous was plugged
/// into ti-pki; that is a programming error, not a runtime condition.
pub fn block_on<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("a blocking transport or store never waits"),
    }
}
