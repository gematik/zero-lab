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

//! Keys of the simulator mode derived from a seed, so that every replica and every run with
//! the same seed has the same keys: what tests that compare output and several replicas of a
//! development deployment need (TASK-389 #3). TEST-ONLY: a derived key is as secret as its
//! seed, and the simulator mode is never in a production build (servers.md rule 17).
//!
//! HKDF-SHA256 (RFC 5869) over the seed, with the kind and the `key_id` as info. An EC
//! scalar that is zero or not below the order is derived again with a counter.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::pkcs11::Curve;

/// The salt of the extraction: names what the keys are for.
const SALT: &[u8] = b"ti-hsm-proxy simulator TEST-ONLY";

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 of `len` bytes, at most 32: one block of the expansion is enough for a scalar
/// of P-256 or P-384 and for an AES-256 key.
fn hkdf(seed: &[u8; 32], info: &[&[u8]], len: usize) -> Vec<u8> {
    let prk = hmac(SALT, &[seed]);
    let mut out = Vec::with_capacity(len);
    let mut block: Vec<u8> = Vec::new();
    for counter in 1u8.. {
        let mut parts: Vec<&[u8]> = vec![&block];
        parts.extend_from_slice(info);
        let counter = [counter];
        parts.push(&counter);
        block = hmac(&prk, &parts).to_vec();
        out.extend_from_slice(&block);
        if out.len() >= len {
            break;
        }
    }
    out.truncate(len);
    out
}

/// The signing key of `key_id` on `curve`, as `seed` derives it: its scalar and its
/// uncompressed public point. `None` for a curve the simulator does not derive.
pub(crate) fn signing_key(
    seed: &[u8; 32],
    key_id: &str,
    curve: Curve,
) -> Option<(Vec<u8>, Vec<u8>)> {
    for attempt in 0u32.. {
        let attempt = attempt.to_be_bytes();
        let info: [&[u8]; 4] = [
            b"ecdsa/",
            curve_name(curve)?.as_bytes(),
            key_id.as_bytes(),
            &attempt,
        ];
        let scalar = hkdf(seed, &info, curve.field_len());
        let point = match curve {
            Curve::P256 => p256::SecretKey::from_slice(&scalar)
                .ok()
                .map(|key| key.public_key().to_sec1_bytes().to_vec()),
            Curve::P384 => p384::SecretKey::from_slice(&scalar)
                .ok()
                .map(|key| key.public_key().to_sec1_bytes().to_vec()),
            _ => return None,
        };
        if let Some(point) = point {
            return Some((scalar, point));
        }
    }
    None
}

/// The AES-256 key-encryption key of `key_id`, as `seed` derives it.
pub(crate) fn key_encryption_key(seed: &[u8; 32], key_id: &str) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(&hkdf(seed, &[b"aes-256-gcm/", key_id.as_bytes()], 32));
    value
}

fn curve_name(curve: Curve) -> Option<&'static str> {
    match curve {
        Curve::P256 => Some("P-256/"),
        Curve::P384 => Some("P-384/"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 A.1 does not fit this HKDF's fixed salt, so the expansion is held to an
    /// independent computation: two blocks of HMAC-SHA256 as the RFC writes them.
    #[test]
    fn rfc_5869_the_expansion_chains_its_blocks() {
        let seed = [7u8; 32];
        let prk = hmac(SALT, &[&seed]);
        let t1 = hmac(&prk, &[b"info", &[1]]);
        let t2 = hmac(&prk, &[&t1, b"info", &[2]]);
        assert_eq!(hkdf(&seed, &[b"info"], 32), t1.to_vec());
        assert_eq!(hkdf(&seed, &[b"info"], 48), [&t1[..], &t2[..16]].concat());
    }

    /// TASK-389 #3: one seed and key_id give one key, another key_id or seed another.
    #[test]
    fn task_389_3_a_seed_derives_the_same_key_every_time() {
        let point = |seed: &[u8; 32], id: &str| signing_key(seed, id, Curve::P256).unwrap().1;
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(point(&a, "sig"), point(&a, "sig"));
        assert_ne!(point(&a, "sig"), point(&a, "other"));
        assert_ne!(point(&a, "sig"), point(&b, "sig"));
        assert_eq!(point(&a, "sig").len(), 65);
        assert_eq!(key_encryption_key(&a, "kek"), key_encryption_key(&a, "kek"));
        assert_ne!(key_encryption_key(&a, "kek"), key_encryption_key(&b, "kek"));
        assert!(signing_key(&a, "sig", Curve::BrainpoolP256r1).is_none());
    }
}
