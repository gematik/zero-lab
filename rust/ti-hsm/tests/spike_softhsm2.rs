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

//! The SoftHSM2 spike of TASK-389: the sidecar's PKCS#11 path driven through a software
//! token, and what the token did, as assertions. `docs/spike-softhsm2.md` reads them out.
//!
//! Gated: `TI_HSM_PKCS11_MODULE_PATH` names the module (SoftHSM2's `libsofthsm2.so`), and
//! `SOFTHSM2_CONF` a configuration whose token directory may be written. `just hsm-spike`
//! sets both, with a fresh token directory, and runs the suite. The token is provisioned
//! by the suite with TEST-ONLY PINs; no key leaves it.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use cryptoki::error::RvError;
use cryptoki::mechanism::MechanismType;
use cryptoki::types::AuthPin;
use ecdsa::signature::hazmat::PrehashVerifier as _;
use sha2::Digest as _;
use ti_hsm::{Curve, Error, Iv, KeyFacts, MessageDigest, Module, SignInput, SigningKey, Token};

const TOKEN: &str = "ti-hsm-spike";

fn user_pin() -> AuthPin {
    AuthPin::from("user-pin-TEST-ONLY")
}

fn module() -> &'static Module {
    static MODULE: OnceLock<Module> = OnceLock::new();
    MODULE.get_or_init(|| {
        let path = std::env::var_os("TI_HSM_PKCS11_MODULE_PATH")
            .map(PathBuf::from)
            .expect("TI_HSM_PKCS11_MODULE_PATH: the PKCS#11 module to drive (just hsm-spike)");
        let module = Module::load(&path).expect("the module loads");
        module
            .provision(TOKEN, &AuthPin::from("so-pin-TEST-ONLY"), &user_pin())
            .expect("the token is provisioned");
        module
    })
}

fn token() -> Token {
    module()
        .open(TOKEN, &user_pin())
        .expect("a session on the token")
}

fn return_code<T: std::fmt::Debug>(result: Result<T, Error>) -> Option<RvError> {
    result.expect_err("the token refused").return_code()
}

/// Verifies `signature` (r and s) of `key` over `digest` with an implementation that is
/// not the token's.
fn verifies(token: &Token, key: &SigningKey, digest: &[u8], signature: &[u8]) -> bool {
    let point = token.public_point(key).expect("the public point");
    match key.curve() {
        Curve::P256 => {
            let key = ecdsa::VerifyingKey::<p256::NistP256>::from_sec1_bytes(&point).unwrap();
            let sig = ecdsa::Signature::<p256::NistP256>::from_slice(signature).unwrap();
            key.verify_prehash(digest, &sig).is_ok()
        }
        Curve::P384 => {
            let key = ecdsa::VerifyingKey::<p384::NistP384>::from_sec1_bytes(&point).unwrap();
            let sig = ecdsa::Signature::<p384::NistP384>::from_slice(signature).unwrap();
            key.verify_prehash(digest, &sig).is_ok()
        }
        Curve::BrainpoolP256r1 => {
            let key =
                ecdsa::VerifyingKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(&point).unwrap();
            let sig = ecdsa::Signature::<bp256::BrainpoolP256r1>::from_slice(signature).unwrap();
            key.verify_prehash(digest, &sig).is_ok()
        }
        _ => unreachable!("a curve the spike does not make"),
    }
}

fn digest(algorithm: MessageDigest, message: &[u8]) -> Vec<u8> {
    match algorithm {
        MessageDigest::Sha256 => sha2::Sha256::digest(message).to_vec(),
        MessageDigest::Sha384 => sha2::Sha384::digest(message).to_vec(),
        MessageDigest::Sha512 => sha2::Sha512::digest(message).to_vec(),
    }
}

/// TASK-389 #7: the token lists every mechanism the HSM proxy interface needs: key pair and
/// key generation, ECDSA over a digest and over a message with SHA-256, SHA-384 and SHA-512,
/// and AES-GCM.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_7_the_token_lists_the_mechanisms_the_interface_needs() {
    let token = token();
    for mechanism in [
        MechanismType::ECC_KEY_PAIR_GEN,
        MechanismType::AES_KEY_GEN,
        MechanismType::ECDSA,
        MechanismType::ECDSA_SHA256,
        MechanismType::ECDSA_SHA384,
        MechanismType::ECDSA_SHA512,
        MechanismType::AES_GCM,
    ] {
        assert!(token.has_mechanism(mechanism).unwrap(), "{mechanism}");
    }
    assert!(module().describe().unwrap().contains("PKCS#11"));
}

/// TASK-389 #4: a signing key is made on the token sensitive and not extractable, and has
/// been so from the start; it signs and does nothing else, and the token refuses another
/// use with CKR_KEY_FUNCTION_NOT_PERMITTED.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_4_a_signing_key_stays_on_the_token_and_only_signs() {
    let token = token();
    for curve in [Curve::P256, Curve::P384] {
        let key = token
            .signing_key(&format!("only-signs-{curve:?}"), curve)
            .unwrap();
        assert_eq!(
            token.signing_key_facts(&key).unwrap(),
            KeyFacts {
                sensitive: Some(true),
                always_sensitive: Some(true),
                extractable: Some(false),
                never_extractable: Some(true),
                sign: Some(true),
                // SoftHSM2 does not report CKA_ENCRYPT and CKA_WRAP of a private key.
                encrypt: None,
                decrypt: Some(false),
                wrap: None,
                unwrap: Some(false),
                derive: Some(false),
            },
            "{curve:?}"
        );
        assert_eq!(
            return_code(token.misuse_signing_key(&key)),
            Some(RvError::KeyFunctionNotPermitted),
            "{curve:?}"
        );
    }
}

/// TASK-389 #4: a key-encryption key is made sensitive and not extractable; it encrypts and
/// decrypts and does nothing else. Its value is not given out, and signing with it is
/// refused with CKR_KEY_FUNCTION_NOT_PERMITTED.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_4_a_key_encryption_key_stays_on_the_token_and_only_encrypts_and_decrypts() {
    let token = token();
    let key = token.key_encryption_key("only-encrypts").unwrap();
    assert_eq!(
        token.key_encryption_key_facts(&key).unwrap(),
        KeyFacts {
            sensitive: Some(true),
            always_sensitive: Some(true),
            extractable: Some(false),
            never_extractable: Some(true),
            sign: Some(false),
            encrypt: Some(true),
            decrypt: Some(true),
            wrap: Some(false),
            unwrap: Some(false),
            derive: Some(false),
        }
    );
    // The token answers CKR_ATTRIBUTE_SENSITIVE; cryptoki reports the attribute as absent.
    let refused = token.read_secret_value(&key).unwrap_err();
    assert!(
        refused.to_string().contains("does not report Value"),
        "{refused}"
    );
    assert_eq!(
        return_code(token.misuse_key_encryption_key(&key)),
        Some(RvError::KeyFunctionNotPermitted)
    );
}

/// TASK-389 #5: a signature over a digest the caller made (CKM_ECDSA) is r and s of the
/// curve's length and verifies with another implementation. A digest of another length
/// than the curve's is refused before the token sees it.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_5_a_signature_over_a_digest_verifies_with_another_implementation() {
    let token = token();
    for (curve, algorithm) in [
        (Curve::P256, MessageDigest::Sha256),
        (Curve::P384, MessageDigest::Sha384),
    ] {
        let key = token
            .signing_key(&format!("digest-{curve:?}"), curve)
            .unwrap();
        let digest = digest(algorithm, b"what the TLS handshake signs");
        let signature = token.sign(&key, SignInput::Digest(&digest)).unwrap();
        assert_eq!(signature.len(), 2 * curve.field_len(), "{curve:?}");
        assert!(verifies(&token, &key, &digest, &signature), "{curve:?}");
        let other = digest[..digest.len() - 1].to_vec();
        assert!(
            matches!(
                token.sign(&key, SignInput::Digest(&other)),
                Err(Error::Input(_))
            ),
            "{curve:?}"
        );
    }
}

/// TASK-389 #5: a message is hashed by the token with SHA-256, SHA-384 or SHA-512 and
/// signed (CKM_ECDSA_SHA*), on either curve; the signature verifies over the digest an
/// independent implementation computes.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_5_a_signature_over_a_message_verifies_with_another_implementation() {
    let token = token();
    let message = b"a JWT's signing input";
    for curve in [Curve::P256, Curve::P384] {
        let key = token
            .signing_key(&format!("message-{curve:?}"), curve)
            .unwrap();
        for algorithm in [
            MessageDigest::Sha256,
            MessageDigest::Sha384,
            MessageDigest::Sha512,
        ] {
            let signature = token
                .sign(&key, SignInput::Message(message, algorithm))
                .unwrap();
            assert_eq!(
                signature.len(),
                2 * curve.field_len(),
                "{curve:?} {algorithm:?}"
            );
            assert!(
                verifies(&token, &key, &digest(algorithm, message), &signature),
                "{curve:?} {algorithm:?}"
            );
        }
    }
}

/// TASK-389 #5: brainpoolP256r1, which the TI uses and the interface does not name, is a
/// curve this token makes keys on and signs with; the signature verifies with another
/// implementation.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_5_brainpool_p256r1_is_a_curve_this_token_signs_on() {
    let token = token();
    let key = token
        .signing_key("brainpool", Curve::BrainpoolP256r1)
        .unwrap();
    let digest = digest(MessageDigest::Sha256, b"an IDP challenge");
    let signature = token.sign(&key, SignInput::Digest(&digest)).unwrap();
    assert!(verifies(&token, &key, &digest, &signature));
    let signature = token
        .sign(
            &key,
            SignInput::Message(b"an IDP challenge", MessageDigest::Sha256),
        )
        .unwrap();
    assert!(verifies(&token, &key, &digest, &signature));
}

/// TASK-389 #5: AES-256-GCM encrypts and decrypts with and without associated data and for
/// an empty plaintext; the tag is 16 bytes and the IV 12. Another associated data, a
/// changed tag or a changed ciphertext is refused with CKR_ENCRYPTED_DATA_INVALID.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_5_aes_gcm_authenticates_the_associated_data() {
    let token = token();
    let key = token.key_encryption_key("gcm").unwrap();
    for (plaintext, aad) in [
        (&b"a 32-byte data encryption key..."[..], &b"row 17"[..]),
        (b"no associated data", b""),
        (b"", b"only associated data"),
    ] {
        let sealed = token.encrypt(&key, plaintext, aad, Iv::Random).unwrap();
        assert_eq!((sealed.iv.len(), sealed.tag.len()), (12, 16));
        assert_eq!(sealed.ciphertext.len(), plaintext.len());
        assert_eq!(token.decrypt(&key, &sealed, aad).unwrap(), plaintext);

        assert_eq!(
            return_code(token.decrypt(&key, &sealed, b"row 18")),
            Some(RvError::EncryptedDataInvalid)
        );
        let mut tag = sealed.clone();
        tag.tag[0] ^= 1;
        assert_eq!(
            return_code(token.decrypt(&key, &tag, aad)),
            Some(RvError::EncryptedDataInvalid)
        );
        if !plaintext.is_empty() {
            let mut ciphertext = sealed.clone();
            ciphertext.ciphertext[0] ^= 1;
            assert_eq!(
                return_code(token.decrypt(&key, &ciphertext, aad)),
                Some(RvError::EncryptedDataInvalid)
            );
        }
    }
}

/// TASK-389 #5: who makes the IV. Two random IVs differ; a given IV gives the same output
/// twice, which a test that compares output needs. SoftHSM2 does not make the IV: given the
/// all-zero buffer it encrypts under it and leaves it as it was, and the adapter refuses the
/// result rather than hand out a ciphertext under a fixed IV.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_5_softhsm2_makes_no_gcm_iv_and_the_adapter_says_so() {
    let token = token();
    let key = token.key_encryption_key("iv").unwrap();
    let (one, two) = (
        token.encrypt(&key, b"x", b"", Iv::Random).unwrap(),
        token.encrypt(&key, b"x", b"", Iv::Random).unwrap(),
    );
    assert_ne!(one.iv, two.iv);
    let given = Iv::Given([7; 12]);
    assert_eq!(
        token.encrypt(&key, b"x", b"", given).unwrap(),
        token.encrypt(&key, b"x", b"", given).unwrap()
    );

    let throwaway = token.key_encryption_key("iv-from-token").unwrap();
    assert!(matches!(
        token.encrypt(&throwaway, b"x", b"", Iv::FromToken),
        Err(Error::Unexpected { .. })
    ));
}

/// TASK-389 #3: a key that is asked for and not there is made, and asked for again is the
/// same key; the same label on another curve is refused, not a second key. A label outside
/// its grammar is refused before the token sees it.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_3_a_key_asked_for_is_made_once_and_found_again() {
    let token = token();
    let made = token.signing_key("made-once", Curve::P256).unwrap();
    let found = token.signing_key("made-once", Curve::P256).unwrap();
    assert_eq!(
        token.public_point(&made).unwrap(),
        token.public_point(&found).unwrap()
    );
    assert!(matches!(
        token.signing_key("made-once", Curve::P384),
        Err(Error::KeyMismatch { .. })
    ));
    // Another session sees the same key: it is a token object, not a session object.
    let other = self::token();
    let seen = other.signing_key("made-once", Curve::P256).unwrap();
    assert_eq!(
        token.public_point(&made).unwrap(),
        other.public_point(&seen).unwrap()
    );

    for label in ["", "with space", "tab\t", "ä", &"x".repeat(65)] {
        assert!(
            matches!(token.signing_key(label, Curve::P256), Err(Error::Input(_))),
            "{label:?}"
        );
        assert!(
            matches!(token.key_encryption_key(label), Err(Error::Input(_))),
            "{label:?}"
        );
    }
}

/// TASK-389 #7: SoftHSM2 returns CKA_EC_POINT DER-wrapped in an OCTET STRING, as PKCS#11
/// specifies; the adapter gives out the uncompressed SEC1 point either way.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_7_the_public_point_is_der_wrapped_and_unwrapped_for_the_caller() {
    let token = token();
    for curve in [Curve::P256, Curve::P384] {
        let key = token
            .signing_key(&format!("point-{curve:?}"), curve)
            .unwrap();
        assert!(token.ec_point_is_wrapped(&key).unwrap(), "{curve:?}");
        let point = token.public_point(&key).unwrap();
        assert_eq!(point.len(), 1 + 2 * curve.field_len(), "{curve:?}");
        assert_eq!(point[0], 0x04, "{curve:?}");
    }
}

/// TASK-389: an error names the operation, the key and the PKCS#11 return code, and holds
/// no data.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_an_error_names_the_operation_the_key_and_the_return_code() {
    let token = token();
    let key = token.key_encryption_key("named-in-errors").unwrap();
    let sealed = token
        .encrypt(
            &key,
            b"plaintext-in-no-error",
            b"aad-in-no-error",
            Iv::Random,
        )
        .unwrap();
    let error = token
        .decrypt(&key, &sealed, b"other-aad-in-no-error")
        .unwrap_err()
        .to_string();
    assert!(error.contains("decrypt"), "{error}");
    assert!(error.contains("named-in-errors"), "{error}");
    assert!(error.contains("EncryptedDataInvalid"), "{error}");
    assert!(!error.contains("in-no-error"), "{error}");
}

/// TASK-389: a key found through one session of a pool signs through every other, since a
/// token object has one handle in all sessions of the application; callers on several
/// threads share the pool's sessions, and each signature verifies.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_a_pool_lends_its_sessions_to_callers_on_several_threads() {
    let pool = module()
        .pool(TOKEN, &user_pin(), NonZeroUsize::new(3).unwrap())
        .unwrap();
    assert_eq!(pool.size(), 3);
    let wait = Duration::from_secs(10);
    let key = pool
        .with(wait, |token| token.signing_key("pooled", Curve::P256))
        .unwrap();
    let digest = digest(MessageDigest::Sha256, b"signed through a pool");
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..20 {
                    pool.with(wait, |token| {
                        let signature = token.sign(&key, SignInput::Digest(&digest))?;
                        assert!(verifies(token, &key, &digest, &signature));
                        Ok(())
                    })
                    .unwrap();
                }
            });
        }
    });
}

/// TASK-389: a caller that finds no free session within its wait is refused with Busy,
/// rather than queued without bound; the session given back serves the next caller.
#[test]
#[ignore = "needs TI_HSM_PKCS11_MODULE_PATH: just hsm-spike"]
fn task_389_a_caller_waits_for_a_session_only_as_long_as_it_says() {
    let pool = module()
        .pool(TOKEN, &user_pin(), NonZeroUsize::new(1).unwrap())
        .unwrap();
    let wait = Duration::from_millis(50);
    pool.with(wait, |_held| {
        let refused = pool.with(wait, |_| Ok(())).unwrap_err();
        assert!(matches!(refused, Error::Busy(w) if w == wait), "{refused}");
        Ok(())
    })
    .unwrap();
    pool.with(wait, |_| Ok(())).unwrap();
}
