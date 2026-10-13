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

//! A backend with further curves: [`Extended`] answers from its added providers first
//! and falls back to the base backend. This is how a curve the base backend lacks
//! (brainpoolP256r1 from `jwz-brainpool`) becomes usable for keys and JWE without
//! being a second backend: random source, hashing, AEAD and key wrap stay the base's.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{Aead, Backend, Ecdh, Ecdsa, EdDsa, Hash, KeyWrap, Mac, Rng};
use crate::jwa::{ContentEncryptionAlgorithm, Curve, HashAlgorithm};

/// `base` plus ECDSA and ECDH providers for further curves.
pub struct Extended<B: Backend> {
    base: B,
    ecdsa: Vec<Box<dyn Ecdsa + Send + Sync>>,
    ecdh: Vec<Box<dyn Ecdh + Send + Sync>>,
}

impl<B: Backend> Extended<B> {
    /// `base` with nothing added yet.
    pub fn new(base: B) -> Self {
        Extended {
            base,
            ecdsa: Vec::new(),
            ecdh: Vec::new(),
        }
    }

    /// Adds ECDSA on `provider.curve()`; it takes precedence over the base's.
    #[must_use]
    pub fn with_ecdsa(mut self, provider: Box<dyn Ecdsa + Send + Sync>) -> Self {
        self.ecdsa.push(provider);
        self
    }

    /// Adds ECDH on `provider.curve()`; it takes precedence over the base's.
    #[must_use]
    pub fn with_ecdh(mut self, provider: Box<dyn Ecdh + Send + Sync>) -> Self {
        self.ecdh.push(provider);
        self
    }
}

impl<B: Backend> Backend for Extended<B> {
    fn rng(&self) -> &dyn Rng {
        self.base.rng()
    }

    fn hash(&self, alg: HashAlgorithm) -> Option<&dyn Hash> {
        self.base.hash(alg)
    }

    fn mac(&self, alg: HashAlgorithm) -> Option<&dyn Mac> {
        self.base.mac(alg)
    }

    fn ecdsa(&self, curve: Curve) -> Option<&dyn Ecdsa> {
        match self.ecdsa.iter().find(|p| p.curve() == curve) {
            Some(provider) => Some(provider.as_ref()),
            None => self.base.ecdsa(curve),
        }
    }

    fn eddsa(&self, curve: Curve) -> Option<&dyn EdDsa> {
        self.base.eddsa(curve)
    }

    fn ecdh(&self, curve: Curve) -> Option<&dyn Ecdh> {
        match self.ecdh.iter().find(|p| p.curve() == curve) {
            Some(provider) => Some(provider.as_ref()),
            None => self.base.ecdh(curve),
        }
    }

    fn aead(&self, enc: ContentEncryptionAlgorithm) -> Option<&dyn Aead> {
        self.base.aead(enc)
    }

    fn key_wrap(&self, kek_len: usize) -> Option<&dyn KeyWrap> {
        self.base.key_wrap(kek_len)
    }
}
