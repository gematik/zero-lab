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

//! A backend with further curves: [`Extended`] answers from its added providers first
//! and falls back to the base backend. This is how a curve the base backend lacks
//! (brainpoolP256r1 from `ti_jwz::brainpool`) becomes usable for keys and JWE without
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

#[cfg(test)]
mod tests {
    #![cfg(feature = "crypto-rustcrypto")]

    use super::*;
    use crate::crypto::CryptoError;
    use crate::crypto::rustcrypto::RustCrypto;

    const TEST_CURVE: Curve = Curve::new("X-TEST-256");

    /// The base's P-256 ECDSA under another curve name.
    struct Renamed;

    impl Ecdsa for Renamed {
        fn curve(&self) -> Curve {
            TEST_CURVE
        }
        fn hash(&self) -> HashAlgorithm {
            HashAlgorithm::Sha256
        }
        fn public_key(&self, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
            RustCrypto::new()
                .ecdsa(Curve::P256)
                .unwrap()
                .public_key(secret)
        }
        fn sign(&self, secret: &[u8], msg: &[u8], rng: &dyn Rng) -> Result<Vec<u8>, CryptoError> {
            RustCrypto::new()
                .ecdsa(Curve::P256)
                .unwrap()
                .sign(secret, msg, rng)
        }
        fn verify(&self, public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
            RustCrypto::new()
                .ecdsa(Curve::P256)
                .unwrap()
                .verify(public, msg, sig)
        }
    }

    /// An added provider answers for its own curve only; every other curve and every
    /// other primitive is the base's.
    #[test]
    fn an_added_curve_answers_for_itself_and_the_base_for_everything_else() {
        let backend = Extended::new(RustCrypto::new()).with_ecdsa(Box::new(Renamed));
        assert_eq!(backend.ecdsa(TEST_CURVE).unwrap().curve(), TEST_CURVE);
        assert_eq!(backend.ecdsa(Curve::P256).unwrap().curve(), Curve::P256);
        assert!(backend.ecdsa(Curve::P384).is_none());
        assert!(backend.ecdh(TEST_CURVE).is_none());

        assert_eq!(
            backend.hash(HashAlgorithm::Sha384).unwrap().algorithm(),
            HashAlgorithm::Sha384
        );
        #[cfg(feature = "hmac")]
        assert_eq!(
            backend.mac(HashAlgorithm::Sha512).unwrap().hash(),
            HashAlgorithm::Sha512
        );
        assert_eq!(
            backend.eddsa(Curve::ED25519).unwrap().curve(),
            Curve::ED25519
        );
        assert_eq!(
            backend
                .aead(ContentEncryptionAlgorithm::A256GCM)
                .unwrap()
                .enc(),
            ContentEncryptionAlgorithm::A256GCM
        );
        assert_eq!(backend.key_wrap(24).unwrap().kek_len(), 24);
    }
}
