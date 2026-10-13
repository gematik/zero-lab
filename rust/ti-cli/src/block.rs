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
