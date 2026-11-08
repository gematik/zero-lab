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

//! JWK and keys against the RFC examples (RFC 7515 A.1/A.3, RFC 7517 A, RFC 7638 §3.1,
//! RFC 8037 A), the key-binding rules, and the HSM and KMS seams.
#![cfg(feature = "crypto-rustcrypto")]

use std::sync::Arc;

use jwz::ErrorCode;
use jwz::crypto::Backend;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::jwa::{HashAlgorithm, Registry, SignatureAlgorithm};
use jwz::jwk::{Jwk, JwkSet, KeyMaterial};
use jwz::keys::{KeyAgreement, Signature, SoftwareAgreementKey, SoftwareKey, Verifier};

fn backend() -> Arc<RustCrypto> {
    Arc::new(RustCrypto::new())
}

fn b64(s: &str) -> Vec<u8> {
    jwz::b64::decode(s, "test").unwrap()
}

const RFC7517_A1: &str = r#"{"keys":[
  {"kty":"EC","crv":"P-256",
   "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
   "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
   "use":"enc","kid":"1"},
  {"kty":"RSA",
   "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
   "e":"AQAB","alg":"RS256","kid":"2011-04-29"}]}"#;

#[test]
fn rfc_7517_a_1_public_key_set() {
    let set = JwkSet::parse(RFC7517_A1).unwrap();
    assert_eq!(set.keys.len(), 2);
    let registry = Registry::standard();
    for key in &set.keys {
        key.check(&registry).unwrap();
        assert!(!key.is_private());
    }
    assert_eq!(set.by_kid("1").count(), 1);
    assert_eq!(set.keys[0].key_use.as_deref(), Some("enc"));
}

#[test]
fn rfc_7638_3_1_thumbprint_of_the_rsa_example() {
    let set = JwkSet::parse(RFC7517_A1).unwrap();
    let hash = backend();
    let sha256 = hash.hash(HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        set.keys[1].thumbprint(sha256),
        "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
}

const RFC8037_A1: &str = r#"{"kty":"OKP","crv":"Ed25519",
  "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

#[test]
fn rfc_8037_a_3_thumbprint_and_a_4_signature() {
    let jwk = Jwk::parse(RFC8037_A1).unwrap();
    let backend = backend();
    let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        jwk.thumbprint(sha256),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
    let key = SoftwareKey::from_jwk(
        &jwk,
        SignatureAlgorithm::EDDSA,
        &Registry::standard(),
        backend,
    )
    .unwrap();
    let input = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    let expected = b64(
        "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
    );
    // Ed25519 is deterministic: the signature must be the RFC's exactly.
    assert_eq!(
        jwz::keys::Signer::try_sign(&key, input).unwrap().as_bytes(),
        expected
    );
    key.verify(input, &Signature::from(expected)).unwrap();
}

const RFC7515_A3_KEY: &str = r#"{"kty":"EC","crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
const RFC7515_A3_INPUT: &[u8] = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
const RFC7515_A3_SIG: &str =
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

#[test]
fn rfc_7515_a_3_es256_signature_verifies_and_a_tampered_one_does_not() {
    let jwk = Jwk::parse(RFC7515_A3_KEY).unwrap();
    let key = SoftwareKey::from_jwk(
        &jwk.public(),
        SignatureAlgorithm::ES256,
        &Registry::standard(),
        backend(),
    )
    .unwrap();
    let sig = b64(RFC7515_A3_SIG);
    key.verify(RFC7515_A3_INPUT, &Signature::from(sig.clone()))
        .unwrap();
    let mut tampered = sig;
    tampered[10] ^= 1;
    assert_eq!(
        key.verify(RFC7515_A3_INPUT, &Signature::from(tampered))
            .map_err(|e| e.code()),
        Err(ErrorCode::VerificationFailed)
    );
}

#[cfg(feature = "hmac")]
#[test]
fn rfc_7515_a_1_hs256_signature() {
    let jwk = Jwk::parse(
        r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#,
    )
    .unwrap();
    let key = SoftwareKey::from_jwk(
        &jwk,
        SignatureAlgorithm::HS256,
        &Registry::standard(),
        backend(),
    )
    .unwrap();
    let input = b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    assert_eq!(
        jwz::keys::Signer::try_sign(&key, input).unwrap().as_bytes(),
        b64("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    );
}

#[cfg(feature = "hmac")]
#[test]
fn rfc_7518_3_2_hmac_key_shorter_than_the_hash_is_refused() {
    let jwk = Jwk::parse(r#"{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}"#).unwrap();
    assert_eq!(
        SoftwareKey::from_jwk(
            &jwk,
            SignatureAlgorithm::HS256,
            &Registry::standard(),
            backend()
        )
        .map(|_| ())
        .map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
}

#[test]
fn rfc_7517_4_4_a_key_is_bound_to_its_algorithm() {
    let registry = Registry::standard();
    let ec = Jwk::parse(RFC7515_A3_KEY).unwrap();
    // The RFC's private key belongs to its public key and loads.
    SoftwareKey::from_jwk(&ec, SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let err = |jwk: &Jwk, alg| {
        SoftwareKey::from_jwk(jwk, alg, &registry, backend())
            .map(|_| ())
            .map_err(|e| e.code())
    };
    // An EC key is not an EdDSA key, and reserved algorithms are refused.
    assert_eq!(
        err(&ec, SignatureAlgorithm::EDDSA),
        Err(ErrorCode::KeyMismatch)
    );
    assert_eq!(
        err(&ec, SignatureAlgorithm::ES384),
        Err(ErrorCode::UnsupportedAlgorithm)
    );
    // The key's own alg wins over the caller's.
    let mut named = ec.clone();
    named.alg = Some("ES384".into());
    assert_eq!(
        err(&named, SignatureAlgorithm::ES256),
        Err(ErrorCode::KeyMismatch)
    );
    // A private part that does not belong to the public part.
    let mut forged = ec;
    if let KeyMaterial::Ec(k) = &mut forged.material {
        k.x[0] ^= 1;
    }
    assert_eq!(
        err(&forged, SignatureAlgorithm::ES256),
        Err(ErrorCode::KeyMismatch)
    );
}

#[test]
fn rfc_7518_6_2_1_2_coordinates_have_the_full_length() {
    let short = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7A","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#;
    let jwk = Jwk::parse(short).unwrap();
    assert_eq!(
        jwk.check(&Registry::standard()).map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
    let unknown = r#"{"kty":"EC","crv":"P-257","x":"AA","y":"AA"}"#;
    assert_eq!(
        Jwk::parse(unknown)
            .unwrap()
            .check(&Registry::standard())
            .map_err(|e| e.code()),
        Err(ErrorCode::UnknownCurve)
    );
}

#[test]
fn jwk_parsing_is_strict() {
    for (text, code) in [
        (
            r#"{"kty":"EC","kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#,
            ErrorCode::DuplicateMember,
        ),
        (
            r#"{"kty":"EC","crv":"P-256","x":"AA==","y":"AA"}"#,
            ErrorCode::Base64,
        ),
        (
            r#"{"kty":"EC","crv":"P-256","y":"AA"}"#,
            ErrorCode::MissingMember,
        ),
        (
            r#"{"kty":"EC","crv":7,"x":"AA","y":"AA"}"#,
            ErrorCode::InvalidMember,
        ),
        (r#"{"kty":"XYZ"}"#, ErrorCode::UnsupportedKeyType),
    ] {
        assert_eq!(Jwk::parse(text).map_err(|e| e.code()), Err(code), "{text}");
    }
}

#[test]
fn private_material_never_shows_in_debug_output() {
    let jwk = Jwk::parse(RFC7515_A3_KEY).unwrap();
    let debug = format!("{jwk:?}");
    assert!(debug.contains("Secret(..)"));
    assert!(!debug.contains("142, 155"), "{debug}");
}

#[test]
fn generated_keys_round_trip_through_their_jwk() {
    let registry = Registry::standard();
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::EDDSA] {
        let key = SoftwareKey::generate(alg, &registry, backend())
            .unwrap()
            .with_kid("k1");
        let sig = jwz::keys::Signer::try_sign(&key, b"msg").unwrap();
        let public = key.public_jwk();
        assert!(!public.is_private());
        let parsed = Jwk::parse(&public.to_json()).unwrap();
        assert_eq!(parsed, public);
        let verifier = SoftwareKey::from_jwk(&parsed, alg, &registry, backend()).unwrap();
        verifier.verify(b"msg", &sig).unwrap();
        assert_eq!(
            verifier.verify(b"other", &sig).map_err(|e| e.code()),
            Err(ErrorCode::VerificationFailed)
        );
        assert_eq!(jwz::keys::JwsKey::key_id(&verifier), Some("k1"));
        // A public key cannot sign.
        assert_eq!(
            jwz::keys::Signer::try_sign(&verifier, b"msg").map_err(|e| e.code()),
            Err(ErrorCode::MissingPrivateKey)
        );
    }
}

#[test]
fn ecdh_both_sides_agree() {
    let alice = SoftwareAgreementKey::generate(jwz::jwa::Curve::P256, backend()).unwrap();
    let bob = SoftwareAgreementKey::generate(jwz::jwa::Curve::P256, backend()).unwrap();
    let point = |jwk: Jwk| match jwk.material {
        KeyMaterial::Ec(k) => [vec![4], k.x, k.y].concat(),
        _ => unreachable!(),
    };
    let z1 = alice.agree(&point(bob.public_jwk())).unwrap();
    let z2 = bob.agree(&point(alice.public_jwk())).unwrap();
    assert_eq!(*z1, *z2);
    assert_eq!(z1.len(), 32);
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 7518 Appendix C: Bob's static private key and Alice's ephemeral public point.
const BOB_D: &str = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw";
const ALICE_X: &str = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0";
const ALICE_Y: &str = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps";

/// RFC 7518 Appendix C's Z: the x-coordinate of Bob's scalar times Alice's point.
#[test]
fn sp_800_56a_5_7_1_2_z_is_the_x_coordinate_of_the_shared_point() {
    let backend = backend();
    let ecdh = backend.ecdh(jwz::jwa::Curve::P256).unwrap();
    let alice = [vec![4], b64(ALICE_X), b64(ALICE_Y)].concat();
    let z = ecdh.agree(&b64(BOB_D), &alice).unwrap();
    assert_eq!(
        *z,
        [
            158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196
        ]
    );
}

/// RFC 8725 §3.4: an ECDH-ES peer point is validated before use, so a point off the
/// curve, the point at infinity or a coordinate outside the field never reaches the
/// scalar multiplication (the invalid-curve attack).
#[test]
fn sp_800_56a_5_6_2_3_a_peer_point_off_the_curve_is_refused() {
    let backend = backend();
    let ecdh = backend.ecdh(jwz::jwa::Curve::P256).unwrap();
    let bob = b64(BOB_D);
    let p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    for (point, what) in [
        (
            [vec![4], b64(ALICE_X), b64(BOB_D)].concat(),
            "not on the curve",
        ),
        (vec![0], "the point at infinity"),
        ([vec![4], p, b64(ALICE_Y)].concat(), "x = p"),
        ([vec![4], vec![0; 32], vec![0; 32]].concat(), "(0, 0)"),
    ] {
        assert_eq!(
            ecdh.agree(&bob, &point).map(|_| ()),
            Err(jwz::crypto::CryptoError::InvalidKey),
            "{what}"
        );
    }
}

/// RFC 4231 test cases 2 (a key shorter than the block) and 6 (a key longer than the
/// block, hashed first) for HMAC-SHA-256.
#[cfg(feature = "hmac")]
#[test]
fn rfc_2104_2_hmac_sha_256_of_rfc_4231_test_cases_2_and_6() {
    let backend = backend();
    let mac = backend.mac(HashAlgorithm::Sha256).unwrap();
    assert_eq!(
        mac.compute(b"Jefe", &[b"what do ya want ", b"for nothing?"])
            .unwrap(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    let long_key = [0xaa; 131];
    let tag = hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    let message: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(mac.compute(&long_key, &[message]).unwrap(), tag);
    mac.verify(&long_key, &[message], &tag).unwrap();
    let mut wrong = tag;
    wrong[31] ^= 1;
    assert_eq!(
        mac.verify(&long_key, &[message], &wrong),
        Err(jwz::crypto::CryptoError::VerificationFailed)
    );
}

#[test]
fn rfc_3394_2_key_data_of_fewer_than_two_blocks_is_refused() {
    let backend = backend();
    let kw = backend.key_wrap(16).unwrap();
    let kek = [1u8; 16];
    for cek in [&[][..], &[2; 8], &[2; 12], &[2; 20]] {
        assert_eq!(
            kw.wrap(&kek, cek),
            Err(jwz::crypto::CryptoError::InvalidInput),
            "{} bytes",
            cek.len()
        );
    }
    for wrapped in [&[3u8; 16][..], &[3; 23], &[3; 28]] {
        assert_eq!(
            kw.unwrap(&kek, wrapped).map(|_| ()),
            Err(jwz::crypto::CryptoError::InvalidInput),
            "{} bytes",
            wrapped.len()
        );
    }
}

/// RFC 3394 §4.1 wraps and unwraps; a changed bit anywhere fails the integrity check
/// instead of yielding other key data.
#[test]
fn rfc_3394_2_2_3_a_failed_integrity_check_returns_no_key_data() {
    let backend = backend();
    let kw = backend.key_wrap(16).unwrap();
    let kek = hex("000102030405060708090A0B0C0D0E0F");
    let key_data = hex("00112233445566778899AABBCCDDEEFF");
    let wrapped = hex("1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5");
    assert_eq!(kw.wrap(&kek, &key_data).unwrap(), wrapped);
    assert_eq!(*kw.unwrap(&kek, &wrapped).unwrap(), key_data);
    for byte in 0..wrapped.len() {
        let mut altered = wrapped.clone();
        altered[byte] ^= 0x80;
        assert_eq!(
            kw.unwrap(&kek, &altered).map(|_| ()),
            Err(jwz::crypto::CryptoError::VerificationFailed),
            "byte {byte}"
        );
    }
}

/// RFC 6979 Appendix A.2.5: P-256, SHA-256, message "sample"; the nonce comes from the
/// key and the message, so the signature is the RFC's to the bit.
#[test]
fn rfc_6979_3_2_es256_signs_deterministically() {
    let backend = backend();
    let ecdsa = backend.ecdsa(jwz::jwa::Curve::P256).unwrap();
    let x = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let expected = hex(
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
         F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    );
    for _ in 0..2 {
        assert_eq!(ecdsa.sign(&x, b"sample", backend.rng()).unwrap(), expected);
    }
}

/// RFC 8032 §7.1 TEST 1: the public key of the secret and the signature of the empty
/// message.
#[test]
fn rfc_8032_5_1_ed25519_test_1() {
    let backend = backend();
    let ed25519 = backend.eddsa(jwz::jwa::Curve::ED25519).unwrap();
    let secret = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    assert_eq!(ed25519.public_key(&secret).unwrap(), public);
    assert_eq!(ed25519.sign(&secret, b"").unwrap(), signature);
    ed25519.verify(&public, b"", &signature).unwrap();
}

/// RFC 8032 §5.1.7: the S half of a signature must be below the group order L; S + L
/// satisfies the same equation but is not the signature.
#[test]
fn rfc_8032_5_1_7_s_not_below_l_is_refused() {
    let backend = backend();
    let ed25519 = backend.eddsa(jwz::jwa::Curve::ED25519).unwrap();
    let secret = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = ed25519.public_key(&secret).unwrap();
    let mut signature = ed25519.sign(&secret, b"msg").unwrap();
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    let l = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    let mut carry = 0u16;
    for (s, l) in signature[32..].iter_mut().zip(&l) {
        let sum = u16::from(*s) + u16::from(*l) + carry;
        *s = sum.to_le_bytes()[0];
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        ed25519.verify(&public, b"msg", &signature),
        Err(jwz::crypto::CryptoError::VerificationFailed)
    );
}

/// The signature is `r || s`, 32 bytes each; DER or any other length is refused.
#[test]
fn rfc_7518_3_4_es256_signature_is_r_and_s_of_32_bytes_each() {
    let registry = Registry::standard();
    let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, backend()).unwrap();
    let sig = jwz::keys::Signer::try_sign(&key, b"msg").unwrap();
    assert_eq!(sig.as_bytes().len(), 64);
    key.verify(b"msg", &sig).unwrap();
    let (r, s) = sig.as_bytes().split_at(32);
    let integer = |n: &[u8]| {
        let mut n = n.to_vec();
        if n[0] & 0x80 != 0 {
            n.insert(0, 0);
        }
        [vec![2, u8::try_from(n.len()).unwrap()], n].concat()
    };
    let body = [integer(r), integer(s)].concat();
    let der = [vec![0x30, u8::try_from(body.len()).unwrap()], body].concat();
    let padded = [sig.as_bytes(), &[0]].concat();
    for (bytes, what) in [
        (der, "DER"),
        (padded, "65 bytes"),
        (sig.as_bytes()[..63].to_vec(), "63 bytes"),
    ] {
        assert_eq!(
            key.verify(b"msg", &Signature::from(bytes))
                .map_err(|e| e.code()),
            Err(ErrorCode::VerificationFailed),
            "{what}"
        );
    }
}

#[test]
fn rfc_7517_4_1_kty_is_required_and_case_sensitive() {
    for (text, code) in [
        (
            r#"{"crv":"P-256","x":"AA","y":"AA"}"#,
            ErrorCode::MissingMember,
        ),
        (
            r#"{"kty":"ec","crv":"P-256","x":"AA","y":"AA"}"#,
            ErrorCode::UnsupportedKeyType,
        ),
        (r#"{"kty":"OCT","k":"AQ"}"#, ErrorCode::UnsupportedKeyType),
        (r#"{"kty":1,"k":"AQ"}"#, ErrorCode::InvalidMember),
    ] {
        assert_eq!(Jwk::parse(text).map_err(|e| e.code()), Err(code), "{text}");
    }
}

/// RFC 8037 §2 adds `OKP` to the three key types; anything else is not a key jwz reads.
#[test]
fn rfc_7518_6_1_ec_rsa_and_oct_are_the_key_types() {
    use jwz::jwa::KeyType;
    for (text, kty) in [
        (
            r#"{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"#,
            KeyType::EC,
        ),
        (r#"{"kty":"RSA","n":"AQ","e":"AQAB"}"#, KeyType::RSA),
        (r#"{"kty":"oct","k":"AQ"}"#, KeyType::OCT),
        (r#"{"kty":"OKP","crv":"Ed25519","x":"AA"}"#, KeyType::OKP),
    ] {
        assert_eq!(Jwk::parse(text).unwrap().key_type(), kty, "{text}");
    }
    assert_eq!(
        Jwk::parse(r#"{"kty":"AKP","pub":"AA"}"#).map_err(|e| e.code()),
        Err(ErrorCode::UnsupportedKeyType)
    );
}

#[test]
fn rfc_7517_4_2_use_is_a_string() {
    let key = |value: &str| format!(r#"{{"kty":"oct","k":"AQ","use":{value}}}"#);
    let parsed = Jwk::parse(&key(r#""sig""#)).unwrap();
    assert_eq!(parsed.key_use.as_deref(), Some("sig"));
    assert_eq!(Jwk::parse(&parsed.to_json()).unwrap(), parsed);
    assert_eq!(
        Jwk::parse(&key(r#"["sig"]"#)).map_err(|e| e.code()),
        Err(ErrorCode::InvalidMember)
    );
}

#[test]
fn rfc_7517_4_3_key_ops_is_an_array_of_strings() {
    let key = |ops: &str| format!(r#"{{"kty":"oct","k":"AQ","key_ops":{ops}}}"#);
    let parsed = Jwk::parse(&key(r#"["sign","verify"]"#)).unwrap();
    assert_eq!(
        parsed.key_ops.as_deref(),
        Some(&["sign".to_string(), "verify".to_string()][..])
    );
    assert_eq!(Jwk::parse(&parsed.to_json()).unwrap(), parsed);
    for ops in [r#""sign""#, r#"["sign",1]"#] {
        assert_eq!(
            Jwk::parse(&key(ops)).map_err(|e| e.code()),
            Err(ErrorCode::InvalidMember),
            "{ops}"
        );
    }
}

/// RFC 7517 §4.9: `x5t#S256` is kept as the string it is. jwz does not validate
/// certificates, so a JWK's chain and thumbprint are data for the application.
#[test]
fn rfc_7517_4_7_x5c_is_an_array_of_strings_kept_as_given() {
    let key = |x5c: &str| {
        format!(r#"{{"kty":"EC","crv":"P-256","x":"AA","y":"AA","x5c":{x5c},"x5t#S256":"dA"}}"#)
    };
    let parsed = Jwk::parse(&key(r#"["TUlJQg==","Q0E="]"#)).unwrap();
    assert_eq!(
        parsed.x5c.as_deref(),
        Some(&["TUlJQg==".to_string(), "Q0E=".to_string()][..])
    );
    assert_eq!(parsed.x5t_s256.as_deref(), Some("dA"));
    assert_eq!(Jwk::parse(&parsed.to_json()).unwrap(), parsed);
    for x5c in [r#""TUlJQg==""#, "[1]"] {
        assert_eq!(
            Jwk::parse(&key(x5c)).map_err(|e| e.code()),
            Err(ErrorCode::InvalidMember),
            "{x5c}"
        );
    }
}

/// A key the set cannot read is ignored, as §5 says it should be: an unknown `kty`, a
/// required member missing, a member of the wrong type or encoding. The set itself must be
/// sound: a document that is not a set, or has a duplicate member anywhere, fails whole.
#[test]
fn rfc_7517_5_a_set_ignores_keys_it_cannot_read_but_not_a_broken_document() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"XYZ"},
            {"kty":"oct"},
            {"kty":"oct","k":"AQ=="},
            {"kty":"oct","k":"AQ","kid":7},
            {"kty":"oct","k":"AQ","key_ops":["sign","sign"]},
            {"kty":"oct","k":"AQ","kid":"good"}]}"#,
    )
    .unwrap();
    assert_eq!(set.keys.len(), 1);
    assert_eq!(set.keys[0].kid.as_deref(), Some("good"));
    for text in [
        r#"{"keys":[{"kty":"oct","k":"AQ","k":"Ag"}]}"#,
        r#"{"keys":["x"]}"#,
        r#"{"keys":{}}"#,
        r#"{"keys":[}"#,
        "{}",
    ] {
        assert!(JwkSet::parse(text).is_err(), "{text}");
    }
}

/// `key_ops` values MUST NOT repeat, and with `use` they MUST agree: `sig` with `sign`
/// and `verify`, `enc` with the encryption operations. A `use` the RFC does not define is
/// not judged here; it allows nothing when the key is used.
#[test]
fn rfc_7517_4_3_key_ops_do_not_repeat_and_agree_with_use() {
    let key = |members: &str| Jwk::parse(&format!(r#"{{"kty":"oct","k":"AQ",{members}}}"#));
    for refused in [
        r#""key_ops":["sign","sign"]"#,
        r#""use":"sig","key_ops":["encrypt"]"#,
        r#""use":"sig","key_ops":["verify","wrapKey"]"#,
        r#""use":"enc","key_ops":["sign"]"#,
    ] {
        assert_eq!(
            key(refused).map_err(|e| e.code()),
            Err(ErrorCode::InvalidMember),
            "{refused}"
        );
    }
    for accepted in [
        r#""key_ops":["sign","verify"]"#,
        r#""use":"sig","key_ops":["verify"]"#,
        r#""use":"enc","key_ops":["wrapKey","unwrapKey"]"#,
        r#""use":"tls","key_ops":["sign"]"#,
        r#""key_ops":["frobnicate"]"#,
    ] {
        assert!(key(accepted).is_ok(), "{accepted}");
    }
}

/// A key goes only to what its `use` and `key_ops` allow: a signature key does not
/// encrypt or decrypt, an encryption key does not sign or verify, and a `use` or
/// operation this library does not know allows nothing. A key that states neither allows
/// everything.
#[test]
fn rfc_7517_4_2_a_key_is_used_only_for_what_use_and_key_ops_allow() {
    use jwz::jwk::KeyPurpose;
    let with = |members: &str| {
        let mut text = RFC7515_A3_KEY.trim_end_matches('}').to_string();
        if !members.is_empty() {
            text.push(',');
            text.push_str(members);
        }
        text.push('}');
        Jwk::parse(&text).unwrap()
    };
    let registry = Registry::standard();
    let signs = |jwk: &Jwk| {
        SoftwareKey::from_jwk(jwk, SignatureAlgorithm::ES256, &registry, backend())
            .map(|_| ())
            .map_err(|e| e.code())
    };
    for allowed in ["", r#""use":"sig""#, r#""key_ops":["verify"]"#] {
        assert_eq!(signs(&with(allowed)), Ok(()), "{allowed}");
        assert!(with(allowed).allows(KeyPurpose::Signature), "{allowed}");
    }
    for refused in [
        r#""use":"enc""#,
        r#""use":"tls""#,
        r#""key_ops":["deriveKey"]"#,
        r#""key_ops":["frobnicate"]"#,
    ] {
        assert_eq!(
            signs(&with(refused)),
            Err(ErrorCode::KeyMismatch),
            "{refused}"
        );
    }

    #[cfg(feature = "jwe")]
    {
        use jwz::header::HeaderParams;
        use jwz::jwa::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm};
        use jwz::jwe::{self, EncryptionKey};
        use jwz::keys::SymmetricKey;

        let agrees = |jwk: &Jwk| {
            SoftwareAgreementKey::from_jwk(jwk, &registry, backend())
                .map(|_| ())
                .map_err(|e| e.code())
        };
        let encrypts_to = |jwk: &Jwk| {
            jwe::encrypt(
                b"x",
                KeyEncryptionAlgorithm::ECDH_ES,
                ContentEncryptionAlgorithm::A256GCM,
                EncryptionKey::Public(&jwk.public()),
                HeaderParams::new(),
                &jwz::profile::Profile::strict().policy,
                &registry,
                backend().as_ref(),
            )
            .map(|_| ())
            .map_err(|e| e.code())
        };
        for allowed in ["", r#""use":"enc""#, r#""key_ops":["deriveKey"]"#] {
            assert_eq!(agrees(&with(allowed)), Ok(()), "{allowed}");
            assert_eq!(encrypts_to(&with(allowed)), Ok(()), "{allowed}");
        }
        assert_eq!(
            agrees(&with(r#""key_ops":["encrypt"]"#)),
            Err(ErrorCode::KeyMismatch),
            "encrypt is not decrypt"
        );
        assert_eq!(
            encrypts_to(&with(r#""key_ops":["decrypt"]"#)),
            Err(ErrorCode::KeyMismatch),
            "decrypt is not encrypt"
        );
        for refused in [r#""use":"sig""#, r#""key_ops":["sign","verify"]"#] {
            assert_eq!(
                agrees(&with(refused)),
                Err(ErrorCode::KeyMismatch),
                "{refused}"
            );
            assert_eq!(
                encrypts_to(&with(refused)),
                Err(ErrorCode::KeyMismatch),
                "{refused}"
            );
        }

        let symmetric = |members: &str| {
            let jwk = Jwk::parse(&format!(
                r#"{{"kty":"oct","k":"GZy6sIZ6wl9NJOKB-jnmVQ"{members}}}"#
            ))
            .unwrap();
            SymmetricKey::from_jwk(&jwk, &registry)
                .map(|_| ())
                .map_err(|e| e.code())
        };
        assert_eq!(symmetric(r#","use":"enc""#), Ok(()));
        assert_eq!(symmetric(r#","key_ops":["unwrapKey"]"#), Ok(()));
        assert_eq!(symmetric(r#","use":"sig""#), Err(ErrorCode::KeyMismatch));
        assert_eq!(
            symmetric(r#","key_ops":["sign"]"#),
            Err(ErrorCode::KeyMismatch)
        );
    }
}

#[test]
fn rfc_7518_6_3_an_rsa_key_has_n_and_e() {
    let registry = Registry::standard();
    let key = Jwk::parse(r#"{"kty":"RSA","n":"AQ","e":"AQAB"}"#).unwrap();
    key.check(&registry).unwrap();
    assert!(!key.is_private());
    for text in [r#"{"kty":"RSA","e":"AQAB"}"#, r#"{"kty":"RSA","n":"AQ"}"#] {
        assert_eq!(
            Jwk::parse(text).map_err(|e| e.code()),
            Err(ErrorCode::MissingMember),
            "{text}"
        );
    }
    assert_eq!(
        Jwk::parse(r#"{"kty":"RSA","n":"","e":"AQAB"}"#)
            .unwrap()
            .check(&registry)
            .map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
}

#[test]
fn rfc_7518_6_3_2_crt_parameters_come_together_or_not_at_all() {
    let key = |extra: &str| format!(r#"{{"kty":"RSA","n":"AQ","e":"AQAB","d":"AQ"{extra}}}"#);
    assert!(Jwk::parse(&key("")).unwrap().is_private());
    let all = r#","p":"AQ","q":"AQ","dp":"AQ","dq":"AQ","qi":"AQ""#;
    let parsed = Jwk::parse(&key(all)).unwrap();
    assert_eq!(Jwk::parse(&parsed.to_json()).unwrap(), parsed);
    for extra in [r#","p":"AQ""#, r#","p":"AQ","q":"AQ","dp":"AQ","dq":"AQ""#] {
        assert_eq!(
            Jwk::parse(&key(extra)).map_err(|e| e.code()),
            Err(ErrorCode::MissingMember),
            "{extra}"
        );
    }
}

#[test]
fn rfc_7518_6_4_a_symmetric_key_has_a_non_empty_k() {
    assert_eq!(
        Jwk::parse(r#"{"kty":"oct"}"#).map_err(|e| e.code()),
        Err(ErrorCode::MissingMember)
    );
    assert_eq!(
        Jwk::parse(r#"{"kty":"oct","k":""}"#)
            .unwrap()
            .check(&Registry::standard())
            .map_err(|e| e.code()),
        Err(ErrorCode::KeyLength)
    );
}

/// RFC 7638 §3.2.1: the thumbprint of a private key is that of its public key, and
/// optional members do not change it.
#[test]
fn rfc_7638_3_2_only_the_required_public_members_count() {
    let backend = backend();
    let sha256 = backend.hash(HashAlgorithm::Sha256).unwrap();
    let private = Jwk::parse(RFC7515_A3_KEY).unwrap();
    let mut decorated = private.public();
    decorated.kid = Some("k".into());
    decorated.alg = Some("ES256".into());
    decorated.key_use = Some("sig".into());
    let thumbprint = private.thumbprint(sha256);
    assert_eq!(private.public().thumbprint(sha256), thumbprint);
    assert_eq!(decorated.thumbprint(sha256), thumbprint);
    let mut other = private.public();
    if let KeyMaterial::Ec(k) = &mut other.material {
        k.crv = "P-384".into();
    }
    assert_ne!(other.thumbprint(sha256), thumbprint);
}

#[test]
fn rfc_8037_2_okp_keys_have_the_raw_length_of_their_curve() {
    let registry = Registry::standard();
    let check = |text: &str| {
        Jwk::parse(text)
            .unwrap()
            .check(&registry)
            .map_err(|e| e.code())
    };
    assert_eq!(check(RFC8037_A1), Ok(()));
    for (text, code) in [
        (
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHUQ"}"#,
            ErrorCode::KeyLength,
        ),
        (
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"AA"}"#,
            ErrorCode::KeyLength,
        ),
        (
            r#"{"kty":"OKP","crv":"P-256","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
            ErrorCode::UnknownCurve,
        ),
    ] {
        assert_eq!(check(text), Err(code), "{text}");
    }
    assert_eq!(
        Jwk::parse(r#"{"kty":"OKP","x":"AA"}"#).map_err(|e| e.code()),
        Err(ErrorCode::MissingMember)
    );
}

/// EdDSA takes its curve from the key's `crv`: a key-agreement curve (X25519) does not
/// sign, and an Edwards curve the backend lacks (Ed448) is refused, not replaced.
#[test]
fn rfc_8037_3_1_eddsa_takes_the_curve_from_the_key() {
    let registry = Registry::standard();
    let ed25519 = Jwk::parse(RFC8037_A1).unwrap();
    SoftwareKey::from_jwk(&ed25519, SignatureAlgorithm::EDDSA, &registry, backend()).unwrap();
    let mut x25519 = ed25519.public();
    if let KeyMaterial::Okp(k) = &mut x25519.material {
        k.crv = "X25519".into();
    }
    let ed448 = Jwk::parse(&format!(
        r#"{{"kty":"OKP","crv":"Ed448","x":"{}"}}"#,
        jwz::b64::encode(&[1; 57])
    ))
    .unwrap();
    for (jwk, what) in [(x25519, "X25519"), (ed448, "Ed448")] {
        assert_eq!(
            SoftwareKey::from_jwk(&jwk, SignatureAlgorithm::EDDSA, &registry, backend())
                .map(|_| ())
                .map_err(|e| e.code()),
            Err(ErrorCode::KeyMismatch),
            "{what}"
        );
    }
}

#[cfg(feature = "test-util")]
mod seams {
    use super::*;
    use futures_lite::future;
    use jwz::keys::{AsyncSigner, FixedRng, MockHsm, TestKms};

    #[test]
    fn mock_hsm_signer_holds_only_a_handle() {
        let registry = Registry::standard();
        let hsm = MockHsm::new(backend());
        let signer = hsm.generate(SignatureAlgorithm::ES256, &registry).unwrap();
        assert_eq!(signer.handle(), 0);
        let sig = jwz::keys::Signer::try_sign(&signer, b"msg").unwrap();
        let public = signer.public_jwk().unwrap();
        assert!(!public.is_private());
        SoftwareKey::from_jwk(&public, SignatureAlgorithm::ES256, &registry, backend())
            .unwrap()
            .verify(b"msg", &sig)
            .unwrap();
    }

    #[test]
    fn test_kms_signer_is_pending_until_the_kms_answers() {
        let registry = Registry::standard();
        let rng = Box::new(FixedRng::new(7));
        let backend = Arc::new(RustCrypto::with_rng(rng));
        let key = SoftwareKey::generate(SignatureAlgorithm::ES256, &registry, Arc::clone(&backend))
            .unwrap();
        let (kms, signer) = TestKms::new(key);
        let mut signing = signer.sign_async(b"msg");
        assert!(future::block_on(future::poll_once(&mut signing)).is_none());
        assert_eq!(kms.serve(), 1);
        let sig = future::block_on(signing).unwrap();
        SoftwareKey::from_jwk(
            &kms.public_jwk(),
            SignatureAlgorithm::ES256,
            &registry,
            backend,
        )
        .unwrap()
        .verify(b"msg", &sig)
        .unwrap();
    }

    #[test]
    fn fixed_rng_makes_generation_reproducible() {
        let registry = Registry::standard();
        let make = || {
            let backend = Arc::new(RustCrypto::with_rng(Box::new(FixedRng::new(42))));
            SoftwareKey::generate(SignatureAlgorithm::EDDSA, &registry, backend)
                .unwrap()
                .public_jwk()
        };
        assert_eq!(make(), make());
    }
}

/// A verifier asks a set for the keys that may have signed a JWS: those with the header's
/// `kid`, every key when the header names none (RFC 7517 §4.5, RFC 7515 §4.1.4).
#[test]
fn rfc_7517_4_5_a_set_offers_the_keys_with_the_headers_kid_or_all() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"oct","k":"AQ","kid":"a"},
            {"kty":"oct","k":"Ag","kid":"b"},
            {"kty":"oct","k":"Aw"}]}"#,
    )
    .unwrap();
    let kids = |kid| {
        set.signing_keys(kid, SignatureAlgorithm::HS256)
            .map(|k| k.kid.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(kids(Some("a")), [Some("a".to_owned())]);
    // A key without a kid cannot match a header that names one.
    assert_eq!(kids(Some("c")), Vec::<Option<String>>::new());
    assert_eq!(kids(None).len(), 3);
}

/// A set offers for a signature only keys whose `use` is `sig` and whose `key_ops` allow
/// signing or verifying, or that state neither (RFC 7517 §4.2, §4.3).
#[test]
fn rfc_7517_4_2_a_set_offers_only_keys_its_use_and_key_ops_allow_for_signatures() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"oct","k":"AQ","kid":"enc","use":"enc"},
            {"kty":"oct","k":"AQ","kid":"wrap","key_ops":["wrapKey"]},
            {"kty":"oct","k":"AQ","kid":"sig","use":"sig"},
            {"kty":"oct","k":"AQ","kid":"verify","key_ops":["verify"]},
            {"kty":"oct","k":"AQ","kid":"any"}]}"#,
    )
    .unwrap();
    let kids: Vec<_> = set
        .signing_keys(None, SignatureAlgorithm::HS256)
        .filter_map(|k| k.kid.as_deref())
        .collect();
    assert_eq!(kids, ["sig", "verify", "any"]);
}

/// A key that names its algorithm is offered only for that algorithm (RFC 7517 §4.4).
#[test]
fn rfc_7517_4_4_a_set_offers_no_key_bound_to_another_algorithm() {
    let set = JwkSet::parse(
        r#"{"keys":[
            {"kty":"oct","k":"AQ","kid":"384","alg":"HS384"},
            {"kty":"oct","k":"AQ","kid":"256","alg":"HS256"},
            {"kty":"oct","k":"AQ","kid":"free"}]}"#,
    )
    .unwrap();
    let kids: Vec<_> = set
        .signing_keys(None, SignatureAlgorithm::HS256)
        .filter_map(|k| k.kid.as_deref())
        .collect();
    assert_eq!(kids, ["256", "free"]);
}
