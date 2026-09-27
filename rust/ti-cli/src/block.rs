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
