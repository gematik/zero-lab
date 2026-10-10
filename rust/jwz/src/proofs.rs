//! Kani proofs (`just verify-formal-jwz`) of the parsing-safety invariants whose
//! correctness does not depend on serde: the base64url round trip, the compact splitter, the
//! widening-only composition of policies, and the layout of the Concat KDF. Inputs are
//! bounded; `docs/VERIFIED.md` lists every proof with its bounds.

use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::b64;
use crate::compact;
use crate::crypto::Hash;
use crate::error::ErrorCode;
use crate::jwa::HashAlgorithm;
use crate::profile::{ClaimsPolicy, KeyReferences, same_media_type, union_into};

/// RFC 7515 §2: what is encoded decodes to itself, for every input of `N` bytes.
fn round_trip<const N: usize>() {
    let bytes: [u8; N] = kani::any();
    assert_eq!(b64::decode(&b64::encode(&bytes), "proof").unwrap(), bytes);
}

// One harness per length: the three trailing-byte cases of base64 (1, 2, 3 bytes).
// Canonicity (every accepted spelling is the encoding of its bytes) is base64ct's
// decoder over symbolic strings, which exhausts CBMC's memory; tests and fuzzing cover it.
#[kani::proof]
#[kani::unwind(6)]
fn base64url_round_trip_1() {
    round_trip::<1>();
}

#[kani::proof]
#[kani::unwind(6)]
fn base64url_round_trip_2() {
    round_trip::<2>();
}

#[kani::proof]
#[kani::unwind(6)]
fn base64url_round_trip_3() {
    round_trip::<3>();
}

/// RFC 7515 §7.1 / RFC 7516 §7.1: for every token of up to 6 bytes over `a` and `.`, the
/// size cap is decided first, then the token splits into exactly 3 parts iff it has
/// exactly 2 dots, and the parts are the token's text between the dots.
#[kani::proof]
#[kani::unwind(8)]
fn compact_split_is_exact() {
    let len: usize = kani::any_where(|l| *l <= 6);
    let max_len: usize = kani::any_where(|m| *m <= 7);
    let mut bytes = [b'a'; 6];
    for b in &mut bytes {
        if kani::any() {
            *b = b'.';
        }
    }
    let token = core::str::from_utf8(&bytes[..len]).unwrap();
    let dots = bytes[..len].iter().filter(|b| **b == b'.').count();
    match compact::split::<3>(token, max_len) {
        Err(e) if len > max_len => assert_eq!(e.code(), ErrorCode::TokenTooLarge),
        Err(e) => {
            assert_eq!(e.code(), ErrorCode::Malformed);
            assert_ne!(dots, 2);
        }
        Ok([a, b, c]) => {
            assert!(len <= max_len && dots == 2);
            assert_eq!(a.len() + b.len() + c.len() + 2, len);
            assert!(!a.contains('.') && !b.contains('.') && !c.contains('.'));
        }
    }
}

/// Composition only widens: the union of a list and any 2 values (equal to it, to each
/// other, or not) keeps every element of both, adds nothing else and no duplicates.
#[kani::proof]
#[kani::unwind(4)]
fn policy_union_keeps_both_and_adds_nothing() {
    let a: u8 = kani::any();
    let b: [u8; 2] = kani::any();
    // Reserved up front: the property is about the elements, not about reallocation,
    // whose modelling alone exceeds CBMC's budget.
    let mut union = Vec::with_capacity(3);
    union.push(a);
    union_into(&mut union, &b);
    assert!(union.contains(&a) && union.contains(&b[0]) && union.contains(&b[1]));
    for (i, x) in union.iter().enumerate() {
        assert!(*x == a || b.contains(x));
        assert!(!union[..i].contains(x));
    }
}

/// A key reference either side allows stays allowed in the union, and only those.
#[kani::proof]
fn key_reference_union_is_the_or() {
    let a = KeyReferences {
        jwk: kani::any(),
        jku: kani::any(),
        x5u: kani::any(),
        x5c: kani::any(),
    };
    let b = KeyReferences {
        jwk: kani::any(),
        jku: kani::any(),
        x5u: kani::any(),
        x5c: kani::any(),
    };
    let u = a.union(b);
    assert_eq!(u.jwk, a.jwk || b.jwk);
    assert_eq!(u.jku, a.jku || b.jku);
    assert_eq!(u.x5u, a.x5u || b.x5u);
    assert_eq!(u.x5c, a.x5c || b.x5c);
}

/// Claims policies widen too: no larger skew or age is lost, `exp` is required only if
/// both require it, an issuer or audience survives only if both demand the same.
#[kani::proof]
// `required` is empty: the bound only covers its (empty) retain loop.
#[kani::unwind(2)]
fn claims_policy_union_only_widens() {
    let policy = |issuer: bool, audience: bool| ClaimsPolicy {
        issuer: issuer.then(|| "i".into()),
        audience: audience.then(|| "a".into()),
        leeway: kani::any(),
        require_exp: kani::any(),
        max_age: if kani::any() { Some(kani::any()) } else { None },
        required: Vec::new(),
    };
    let a = policy(kani::any(), kani::any());
    let b = policy(kani::any(), kani::any());
    let u = a.clone().with(&b);
    assert!(u.leeway >= a.leeway && u.leeway >= b.leeway);
    assert_eq!(u.require_exp, a.require_exp && b.require_exp);
    if let Some(age) = u.max_age {
        assert!(a.max_age.is_some_and(|x| age >= x) && b.max_age.is_some_and(|x| age >= x));
    }
    assert!(u.issuer.is_none() || (u.issuer == a.issuer && u.issuer == b.issuer));
    assert!(u.audience.is_none() || (u.audience == a.audience && u.audience == b.audience));
}

/// RFC 7515 §4.1.9: `typ` comparison is symmetric and case-insensitive, for every pair
/// of ASCII strings of up to 3 bytes.
#[kani::proof]
#[kani::unwind(5)]
fn media_type_comparison_is_symmetric_and_case_insensitive() {
    let (a_len, b_len): (usize, usize) =
        (kani::any_where(|l| *l <= 3), kani::any_where(|l| *l <= 3));
    let a_bytes: [u8; 3] = kani::any();
    let b_bytes: [u8; 3] = kani::any();
    kani::assume(a_bytes.is_ascii() && b_bytes.is_ascii());
    let a = core::str::from_utf8(&a_bytes[..a_len]).unwrap();
    let b = core::str::from_utf8(&b_bytes[..b_len]).unwrap();
    assert_eq!(same_media_type(a, b), same_media_type(b, a));
    let mut upper = a_bytes;
    upper.make_ascii_uppercase();
    assert!(same_media_type(
        a,
        core::str::from_utf8(&upper[..a_len]).unwrap()
    ));
}

/// A hash that records its input, so the refusal proof sees that nothing was hashed.
struct Recording(RefCell<Vec<Vec<u8>>>);

impl Hash for Recording {
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha256
    }

    fn digest(&self, parts: &[&[u8]]) -> Vec<u8> {
        self.0.borrow_mut().push(parts.concat());
        vec![0; 32]
    }
}

#[cfg(feature = "jwe")]
/// The KDF refuses a key length whose bit count does not fit SuppPubInfo's 32 bits, and
/// zero, before hashing anything.
#[kani::proof]
// The refusal returns before any loop; the bound only cuts the wipe loop of the
// never-allocated key buffer that CBMC would otherwise unwind for a symbolic length.
#[kani::unwind(2)]
fn concat_kdf_refuses_unrepresentable_lengths() {
    let key_len: usize = kani::any();
    kani::assume(key_len == 0 || key_len > (u32::MAX / 8) as usize);
    let hash = Recording(RefCell::new(Vec::new()));
    let result = crate::jwe::ecdh::concat_kdf(&hash, b"z", b"", b"", b"", key_len);
    assert_eq!(
        result.map(|_| ()).map_err(|e| e.code()),
        Err(ErrorCode::InvalidMember)
    );
    assert!(hash.0.borrow().is_empty());
}
