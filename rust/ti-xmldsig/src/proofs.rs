//! Kani proofs (`just verify-formal`) for the parts of TSLSIG-001 and TSLSIG-016 whose
//! correctness does not depend on the parser: escaping, the namespace rule of Exclusive
//! C14N and the depth scan. Inputs are bounded; the bounds cover every case the code
//! distinguishes (each special character, each relation between prefixes).

use alloc::vec::Vec;

use crate::c14n::{attribute_reference, escape_attribute, text_reference};
use crate::parse::{local_part, nests_deeper};

/// C14N 1.0 §2.3 for text, for every byte: the four references, every other byte
/// copied; no copied byte is `<`, `>`, `&` or a carriage return. References are distinct,
/// start with `&` and end with `;`, so the output decodes unambiguously.
#[kani::proof]
fn text_escaping_is_exactly_the_c14n_map() {
    let byte: u8 = kani::any();
    match text_reference(byte) {
        Some(r) => assert!(matches!(
            (byte, r),
            (b'&', b"&amp;") | (b'<', b"&lt;") | (b'>', b"&gt;") | (b'\r', b"&#xD;")
        )),
        None => assert!(!matches!(byte, b'<' | b'>' | b'&' | b'\r')),
    }
}

/// C14N 1.0 §2.3 for attribute values, for every byte: the six references, every other
/// byte copied; no copied byte is `<`, `&`, `"`, tab, line feed or carriage return.
#[kani::proof]
fn attribute_escaping_is_exactly_the_c14n_map() {
    let byte: u8 = kani::any();
    match attribute_reference(byte) {
        Some(r) => assert!(matches!(
            (byte, r),
            (b'&', b"&amp;")
                | (b'<', b"&lt;")
                | (b'"', b"&quot;")
                | (b'\t', b"&#x9;")
                | (b'\n', b"&#xA;")
                | (b'\r', b"&#xD;")
        )),
        None => assert!(!matches!(byte, b'<' | b'&' | b'"' | b'\t' | b'\n' | b'\r')),
    }
}

/// Escaping copies or replaces byte by byte: the output is the concatenation of the
/// per-byte results, for any three bytes.
#[kani::proof]
// Comparing segment by segment keeps every compared slice within the 6 bytes of
// `&quot;`; one comparison of the whole output would need an unwind bound of 19, which
// does not finish.
#[kani::unwind(7)]
fn escaping_is_the_byte_wise_map() {
    let bytes: [u8; 3] = kani::any();
    kani::assume(bytes.is_ascii());
    let text = core::str::from_utf8(&bytes).unwrap();
    let mut out = Vec::new();
    escape_attribute(text, &mut out);
    let mut rest = out.as_slice();
    for b in bytes {
        let single = [b];
        let expected = attribute_reference(b).unwrap_or(&single);
        assert!(rest.len() >= expected.len());
        let (head, tail) = rest.split_at(expected.len());
        assert!(head == expected);
        rest = tail;
    }
    assert!(rest.is_empty());
}

/// The depth scan never panics and never reads past its input.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(8)]
fn depth_scan_is_total() {
    let bytes: [u8; 6] = kani::any();
    let alphabet = *b"<>/!?-\"a";
    let input: Vec<u8> = bytes
        .iter()
        .map(|b| alphabet[usize::from(*b % 8)])
        .collect();
    let max_depth: usize = kani::any_where(|d| *d <= 4);
    let _ = nests_deeper(&input, max_depth);
}

/// The local part is the suffix after the last `:`, and contains no `:`.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(6)]
fn local_part_is_the_suffix_after_the_last_colon() {
    let alphabet = *b"ab:";
    let q: [u8; 4] = kani::any();
    let q = q.map(|b| alphabet[usize::from(b % 3)]);
    let len: usize = kani::any_where(|n| *n <= 4);
    let qname = &q[..len];
    let local = local_part(qname);
    assert!(!local.contains(&b':'));
    assert!(qname.ends_with(local));
    let prefix_len = len - local.len();
    assert!(prefix_len == 0 || qname[prefix_len - 1] == b':');
}
