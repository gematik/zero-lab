//! Test doubles for downstream tests (feature `test-util`): a fixed random source, an
//! HSM whose signers hold only a handle, and a KMS that signs asynchronously over a
//! request queue. They prove the key seams of ADR 0001 key point 4 without hardware.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use super::{AsyncSigner, JwsKey, Signature, SoftwareKey, to_signature_error};
use crate::crypto::asynchronous::BoxFuture;
use crate::crypto::{Backend, CryptoError, Rng};
use crate::error::{Error, ErrorCode};
use crate::jwa::{Registry, SignatureAlgorithm};
use crate::jwk::Jwk;

/// A deterministic random source (xorshift64*) for reproducible tests. Not random.
pub struct FixedRng {
    // Atomic only so the source is Sync and fits RustCrypto::with_rng; tests use it
    // from one thread.
    state: AtomicU64,
}

impl FixedRng {
    /// A source starting from `seed` (zero is replaced by a fixed non-zero value).
    pub fn new(seed: u64) -> Self {
        FixedRng {
            state: AtomicU64::new(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            }),
        }
    }
}

impl Rng for FixedRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        for chunk in dest.chunks_mut(8) {
            let mut x = self.state.load(Ordering::Relaxed);
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.state.store(x, Ordering::Relaxed);
            let bytes = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(bytes.get(..chunk.len()).unwrap_or_default());
        }
        Ok(())
    }
}

/// An HSM double: it keeps the keys, signers only get a handle.
pub struct MockHsm<B: Backend> {
    backend: Arc<B>,
    keys: RefCell<Vec<SoftwareKey<B>>>,
}

impl<B: Backend> MockHsm<B> {
    /// An empty HSM using `backend` inside.
    pub fn new(backend: Arc<B>) -> Rc<Self> {
        Rc::new(MockHsm {
            backend,
            keys: RefCell::new(Vec::new()),
        })
    }

    /// Generates a key for `alg` inside the HSM and returns its signer.
    ///
    /// # Errors
    ///
    /// As [`SoftwareKey::generate`].
    pub fn generate(
        self: &Rc<Self>,
        alg: SignatureAlgorithm,
        registry: &Registry,
    ) -> Result<MockHsmSigner<B>, Error> {
        let key = SoftwareKey::generate(alg, registry, Arc::clone(&self.backend))?;
        let mut keys = self.keys.borrow_mut();
        let handle = keys.len();
        keys.push(key);
        Ok(MockHsmSigner {
            hsm: Rc::clone(self),
            handle,
            alg,
        })
    }

    fn sign(&self, handle: usize, msg: &[u8]) -> Result<Signature, signature::Error> {
        let keys = self.keys.borrow();
        let key = keys.get(handle).ok_or_else(|| {
            to_signature_error(Error::new(ErrorCode::MissingPrivateKey, "hsm handle"))
        })?;
        signature::Signer::try_sign(key, msg)
    }

    fn public_jwk(&self, handle: usize) -> Option<Jwk> {
        self.keys.borrow().get(handle).map(SoftwareKey::public_jwk)
    }
}

/// A signer that holds only a handle into a [`MockHsm`].
pub struct MockHsmSigner<B: Backend> {
    hsm: Rc<MockHsm<B>>,
    handle: usize,
    alg: SignatureAlgorithm,
}

impl<B: Backend> MockHsmSigner<B> {
    /// The handle, the only thing this signer knows about its key.
    pub fn handle(&self) -> usize {
        self.handle
    }

    /// The public key, as an HSM exports it.
    pub fn public_jwk(&self) -> Option<Jwk> {
        self.hsm.public_jwk(self.handle)
    }
}

impl<B: Backend> JwsKey for MockHsmSigner<B> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl<B: Backend> signature::Signer<Signature> for MockHsmSigner<B> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.hsm.sign(self.handle, msg)
    }
}

/// One signing request in the KMS queue and the slot its answer goes into.
struct Request {
    msg: Vec<u8>,
    reply: Rc<RefCell<Reply>>,
}

#[derive(Default)]
struct Reply {
    result: Option<Result<Signature, Error>>,
    waker: Option<Waker>,
}

/// A KMS double that signs only when [`serve`](Self::serve) runs, the way a remote
/// signer answers later; its [`TestKmsSigner`] is genuinely asynchronous.
pub struct TestKms<B: Backend> {
    key: SoftwareKey<B>,
    queue: Rc<RefCell<VecDeque<Request>>>,
}

impl<B: Backend> TestKms<B> {
    /// A KMS holding `key`, and the signer that talks to it.
    pub fn new(key: SoftwareKey<B>) -> (Self, TestKmsSigner) {
        let queue = Rc::new(RefCell::new(VecDeque::new()));
        let signer = TestKmsSigner {
            queue: Rc::clone(&queue),
            alg: key.algorithm(),
        };
        (TestKms { key, queue }, signer)
    }

    /// Answers every queued request and wakes its waiter; returns how many it answered.
    pub fn serve(&self) -> usize {
        let mut served = 0;
        while let Some(request) = self.queue.borrow_mut().pop_front() {
            let result = super::Signer::try_sign(&self.key, &request.msg);
            let mut reply = request.reply.borrow_mut();
            reply.result = Some(result);
            if let Some(waker) = reply.waker.take() {
                waker.wake();
            }
            served += 1;
        }
        served
    }

    /// The public key.
    pub fn public_jwk(&self) -> Jwk {
        self.key.public_jwk()
    }
}

/// The client side of a [`TestKms`]: signing queues a request and waits for the answer.
pub struct TestKmsSigner {
    queue: Rc<RefCell<VecDeque<Request>>>,
    alg: SignatureAlgorithm,
}

impl JwsKey for TestKmsSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }
}

impl AsyncSigner for TestKmsSigner {
    fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, Error>> {
        let reply = Rc::new(RefCell::new(Reply::default()));
        self.queue.borrow_mut().push_back(Request {
            msg: msg.to_vec(),
            reply: Rc::clone(&reply),
        });
        Box::pin(Pending { reply })
    }
}

/// Waits for the KMS to fill the reply slot.
struct Pending {
    reply: Rc<RefCell<Reply>>,
}

impl Future for Pending {
    type Output = Result<Signature, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut reply = self.reply.borrow_mut();
        if let Some(result) = reply.result.take() {
            Poll::Ready(result)
        } else {
            reply.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
