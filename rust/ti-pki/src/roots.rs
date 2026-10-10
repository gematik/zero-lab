//! Assembly of a [`TrustStore`] from gematik's roots.json,
//! either the copy compiled into the crate or a freshly downloaded one. Every
//! candidate root must chain back to the environment's anchor through the
//! A_28419 cross-certificate protocol: seven checks per candidate, implemented
//! step by step so the code can be read against gemSpec_PKI. The walk follows
//! the anchor's successors forward and its predecessors backward, so a
//! download can only ever add roots that chain to the anchor.
//!
//! A link that fails any step ends that direction of the walk without failing the load:
//! older roots.json layouts contain orientations that cannot be followed, and a root
//! whose key no configured algorithm handles (the RSA roots GEM.RCA2/6/9 without RSA
//! support) cannot be verified. [`Walk`] records where and why each direction stopped.

use base64ct::{Base64, Encoding};
use serde::Deserialize;

use crate::algorithms::AlgorithmSet;
use crate::time::Timestamp;
use crate::{Certificate, Error, TrustConfig, TrustStore};

/// Download point of the production roots.json.
pub const URL_PROD: &str = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// Download point of the reference roots.json, which the development environment shares.
pub const URL_REF: &str = "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// Download point of the test roots.json.
pub const URL_TEST: &str = "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json";

/// gematik's roots.json for production, as published.
pub const ROOTS_PROD: &[u8] = include_bytes!("roots-prod.json");

/// gematik's roots.json for the non-production environments. test and ref publish
/// the same file, so one copy serves dev, ref and test.
#[cfg(feature = "dangerous-nonprod")]
pub const ROOTS_NONPROD: &[u8] = include_bytes!("roots-nonprod.json");

/// One root of a roots.json with its cross certificates, still unverified.
#[derive(Clone, Debug)]
pub struct RootsEntry {
    /// The self-signed root.
    pub cert: Certificate,
    /// The entry's `cn` field.
    pub cn: String,
    prev: Option<Vec<u8>>,
    next: Option<Vec<u8>>,
}

/// Parses a roots.json in either form gematik ships: a bare array (dev, ref, prod) or an
/// object `{"roots": [...]}` (test).
///
/// # Errors
///
/// [`Error::Malformed`] for JSON that is neither form, an empty list, or an entry whose
/// root certificate does not decode. Cross certificates are decoded only when the walk
/// reaches them.
pub fn parse(json: &[u8]) -> Result<Vec<RootsEntry>, Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Document {
        List(Vec<RawEntry>),
        Wrapped { roots: Vec<RawEntry> },
    }
    #[derive(Deserialize)]
    struct RawEntry {
        cert: String,
        #[serde(default)]
        cn: String,
        #[serde(default)]
        prev: Option<String>,
        #[serde(default)]
        next: Option<String>,
    }

    let raw = match serde_json::from_slice(json).map_err(|e| malformed(e.to_string()))? {
        Document::List(entries) | Document::Wrapped { roots: entries } => entries,
    };
    if raw.is_empty() {
        return Err(malformed("roots.json is empty".into()));
    }
    let base64 = |field: Option<String>| -> Result<Option<Vec<u8>>, Error> {
        field
            .filter(|s| !s.is_empty())
            .map(|s| Base64::decode_vec(&s).map_err(|e| malformed(e.to_string())))
            .transpose()
    };
    raw.into_iter()
        .map(|entry| {
            let der = Base64::decode_vec(&entry.cert)
                .map_err(|e| malformed(format!("root {:?}: {e}", entry.cn)))?;
            let cert = Certificate::from_der(&der)
                .map_err(|e| malformed(format!("root {:?}: {e}", entry.cn)))?;
            Ok(RootsEntry {
                cert,
                prev: base64(entry.prev)?,
                next: base64(entry.next)?,
                cn: entry.cn,
            })
        })
        .collect()
}

fn malformed(reason: String) -> Error {
    Error::Malformed {
        what: "roots.json",
        reason,
    }
}

/// The result of an A_28419 walk: the roots that chain to the anchor, and where the
/// walk stopped in each direction if it did not simply run out of links.
#[derive(Clone, Debug)]
pub struct Walk {
    /// The anchor first, then successors, then predecessors.
    pub trusted: Vec<Certificate>,
    /// Why the forward walk (towards newer roots) stopped early.
    pub forward_stop: Option<String>,
    /// Why the backward walk (towards older roots) stopped early.
    pub backward_stop: Option<String>,
}

impl Walk {
    /// The trusted roots as a store.
    pub fn store(&self) -> TrustStore {
        TrustStore::new(self.trusted.iter().cloned())
    }
}

/// Walks `entries` from `anchor` through their `next` and `prev` cross certificates,
/// importing each root whose link passes all seven A_28419 checks at `now`.
///
/// # Errors
///
/// [`Error::Malformed`] if `anchor` is not one of the entries.
pub fn walk(
    anchor: &Certificate,
    entries: &[RootsEntry],
    now: Timestamp,
    algorithms: &AlgorithmSet,
) -> Result<Walk, Error> {
    let anchor_idx = entries
        .iter()
        .position(|e| e.cert == *anchor)
        .ok_or_else(|| {
            malformed(format!(
                "trust anchor {:?} not present in roots.json",
                anchor.subject_cn()
            ))
        })?;
    let mut trusted = vec![entries[anchor_idx].cert.clone()];
    let forward_stop = walk_direction(
        entries,
        anchor_idx,
        |e| e.next.as_deref(),
        &mut trusted,
        now,
        algorithms,
    );
    let backward_stop = walk_direction(
        entries,
        anchor_idx,
        |e| e.prev.as_deref(),
        &mut trusted,
        now,
        algorithms,
    );
    Ok(Walk {
        trusted,
        forward_stop,
        backward_stop,
    })
}

fn walk_direction(
    entries: &[RootsEntry],
    start: usize,
    link: fn(&RootsEntry) -> Option<&[u8]>,
    trusted: &mut Vec<Certificate>,
    now: Timestamp,
    algorithms: &AlgorithmSet,
) -> Option<String> {
    let mut current = start;
    while let Some(cross_der) = link(&entries[current]) {
        let from = entries[current].cert.subject_cn();
        let cross = match Certificate::from_der(cross_der) {
            Ok(cross) => cross,
            Err(e) => {
                return Some(format!(
                    "cross certificate from {from:?} does not parse: {e}"
                ));
            }
        };
        let Some(next) = entries.iter().position(|e| {
            e.cert.subject_key_id().is_some() && e.cert.subject_key_id() == cross.subject_key_id()
        }) else {
            return Some(format!(
                "cross certificate from {from:?} names a root not in roots.json"
            ));
        };
        let candidate = &entries[next].cert;
        if trusted.contains(candidate) {
            return Some(format!(
                "cross certificate from {from:?} loops back to {:?}",
                candidate.subject_cn()
            ));
        }
        if let Err(e) =
            verify_cross_signed(&entries[current].cert, &cross, candidate, now, algorithms)
        {
            return Some(format!("{:?} not imported: {e}", candidate.subject_cn()));
        }
        trusted.push(candidate.clone());
        current = next;
    }
    None
}

/// An A_28419 check failed; `step` numbers it as in gemSpec_PKI.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("A_28419 step {step}: {reason}")]
pub struct CrossCertError {
    /// The failed step, 1 to 7.
    pub step: u8,
    /// What failed.
    pub reason: String,
}

/// The seven A_28419 checks for importing `subordinate` as a new root on the strength
/// of `cross`, a certificate for the subordinate's name and key issued by `anchor`.
///
/// 1. `cross` is signed by the already trusted `anchor`;
/// 2. `cross` is valid at `now`;
/// 3. `cross`'s common name matches `GEM.RCA<n>`;
/// 4. `cross` and `subordinate` have the same subject key identifier;
/// 5. … the same common name;
/// 6. … the same public key;
/// 7. `subordinate`'s self-signature verifies under `cross`'s key.
///
/// # Errors
///
/// The first failing step.
pub fn verify_cross_signed(
    anchor: &Certificate,
    cross: &Certificate,
    subordinate: &Certificate,
    now: Timestamp,
    algorithms: &AlgorithmSet,
) -> Result<(), CrossCertError> {
    let fail = |step, reason: String| Err(CrossCertError { step, reason });
    if let Err(e) = cross.verify_signed_by(anchor, algorithms) {
        return fail(
            1,
            format!(
                "cross {:?} is not signed by anchor {:?}: {e}",
                cross.subject_cn(),
                anchor.subject_cn()
            ),
        );
    }
    if now < cross.not_before() {
        return fail(
            2,
            format!(
                "cross {:?} not yet valid (notBefore {})",
                cross.subject_cn(),
                cross.not_before()
            ),
        );
    }
    if now > cross.not_after() {
        return fail(
            2,
            format!(
                "cross {:?} expired (notAfter {})",
                cross.subject_cn(),
                cross.not_after()
            ),
        );
    }
    if !is_rca_name(cross.subject_cn()) {
        return fail(
            3,
            format!("{:?} does not match GEM.RCA<n>", cross.subject_cn()),
        );
    }
    if cross.subject_key_id().is_none() || cross.subject_key_id() != subordinate.subject_key_id() {
        return fail(
            4,
            "subject key identifier differs from the subordinate's".into(),
        );
    }
    if cross.subject_cn() != subordinate.subject_cn() {
        return fail(
            5,
            format!(
                "common name {:?} differs from the subordinate's {:?}",
                cross.subject_cn(),
                subordinate.subject_cn()
            ),
        );
    }
    if cross.public_key_info() != subordinate.public_key_info() {
        return fail(6, "public key differs from the subordinate's".into());
    }
    if let Err(e) = subordinate.verify_signed_by(cross, algorithms) {
        return fail(
            7,
            format!(
                "subordinate {:?} does not verify under the cross certificate: {e}",
                subordinate.subject_cn()
            ),
        );
    }
    Ok(())
}

fn is_rca_name(cn: &str) -> bool {
    cn.strip_prefix("GEM.RCA")
        .and_then(|rest| rest.chars().next())
        .is_some_and(|c| c.is_ascii_digit())
}

/// The trust store `config` describes: the anchor, plus every root of `config.roots`
/// that the A_28419 walk reaches at `now`. Without roots.json, the anchor alone.
///
/// # Errors
///
/// [`Error::Der`] if the anchor does not parse, [`Error::Malformed`] if roots.json does
/// not parse or does not contain the anchor.
pub fn load(config: &TrustConfig, now: Timestamp) -> Result<Walk, Error> {
    let anchor = Certificate::from_der(&config.anchor)?;
    if config.roots.is_empty() {
        return Ok(Walk {
            trusted: vec![anchor],
            forward_stop: None,
            backward_stop: None,
        });
    }
    walk(&anchor, &parse(&config.roots)?, now, &config.algorithms)
}

/// Verifies roots.json against `anchor` for the loading layer.
#[cfg(feature = "load")]
pub(crate) fn verify_roots_json(
    anchor: &[u8],
    roots_json: &[u8],
    now: Timestamp,
    algorithms: &AlgorithmSet,
) -> Result<Vec<Certificate>, crate::load::VerifyError> {
    let to_verify_error = |e: Error| crate::load::VerifyError::new(e.to_string());
    let anchor = Certificate::from_der(anchor).map_err(to_verify_error)?;
    let entries = parse(roots_json).map_err(to_verify_error)?;
    Ok(walk(&anchor, &entries, now, algorithms)
        .map_err(to_verify_error)?
        .trusted)
}

#[cfg(all(test, feature = "brainpool"))]
mod tests {
    use super::*;
    use crate::algorithms::DEFAULT;
    use crate::testing::{RootsEntry as Entry, TestPki, roots_json};

    const NOW: Timestamp = TestPki::NOW;

    fn cns(certs: &[Certificate]) -> Vec<&str> {
        certs.iter().map(Certificate::subject_cn).collect()
    }

    #[test]
    fn cross_signed_happy_path() {
        let pki = TestPki::new();
        verify_cross_signed(&pki.rca1, &pki.cross_rca1_for_rca7, &pki.rca7, NOW, DEFAULT).unwrap();
    }

    #[test]
    fn cross_signed_by_another_root_fails_step_1() {
        let pki = TestPki::new();
        let error = verify_cross_signed(
            &pki.rogue_root,
            &pki.cross_rca1_for_rca7,
            &pki.rca7,
            NOW,
            DEFAULT,
        )
        .unwrap_err();
        assert_eq!(error.step, 1);
    }

    #[test]
    fn expired_cross_fails_step_2() {
        let pki = TestPki::new();
        let later = Timestamp(pki.cross_rca1_for_rca7.not_after().0 + 3600);
        let error = verify_cross_signed(
            &pki.rca1,
            &pki.cross_rca1_for_rca7,
            &pki.rca7,
            later,
            DEFAULT,
        )
        .unwrap_err();
        assert_eq!(error.step, 2);
    }

    #[test]
    fn other_subordinate_fails_step_4() {
        let pki = TestPki::new();
        let error = verify_cross_signed(
            &pki.rca1,
            &pki.cross_rca1_for_rca7,
            &pki.sub_ca_hba,
            NOW,
            DEFAULT,
        )
        .unwrap_err();
        assert_eq!(error.step, 4);
    }

    #[test]
    fn non_rca_name_fails_step_3() {
        let pki = TestPki::new();
        let cross = &pki.cross_rca1_not_rca;
        let error = verify_cross_signed(&pki.rca1, cross, &pki.rca7, NOW, DEFAULT).unwrap_err();
        assert_eq!(error.step, 3);
    }

    #[test]
    fn walk_follows_the_cross_certificate() {
        let pki = TestPki::new();
        let json = roots_json(&[
            Entry {
                cert: &pki.rca1,
                prev: None,
                next: Some(&pki.cross_rca1_for_rca7),
            },
            Entry {
                cert: &pki.rca7,
                prev: None,
                next: None,
            },
        ]);
        let entries = parse(&json).unwrap();

        let from_rca1 = walk(&pki.rca1, &entries, NOW, DEFAULT).unwrap();
        assert_eq!(
            cns(&from_rca1.trusted),
            ["GEM.RCA1 TEST-ONLY", "GEM.RCA7 TEST-ONLY"]
        );
        assert_eq!(
            (from_rca1.forward_stop, from_rca1.backward_stop),
            (None, None)
        );

        // Trust only flows along a cross certificate, never against it.
        let from_rca7 = walk(&pki.rca7, &entries, NOW, DEFAULT).unwrap();
        assert_eq!(cns(&from_rca7.trusted), ["GEM.RCA7 TEST-ONLY"]);
    }

    #[test]
    fn walk_stops_at_a_failing_link_without_failing_the_load() {
        let pki = TestPki::new();
        let json = roots_json(&[
            Entry {
                cert: &pki.rca1,
                prev: None,
                next: Some(&pki.cross_rca1_for_rca7),
            },
            Entry {
                cert: &pki.rca7,
                prev: None,
                next: None,
            },
        ]);
        let later = Timestamp(pki.cross_rca1_for_rca7.not_after().0 + 1);
        let result = walk(&pki.rca1, &parse(&json).unwrap(), later, DEFAULT).unwrap();
        assert_eq!(cns(&result.trusted), ["GEM.RCA1 TEST-ONLY"]);
        assert!(result.forward_stop.unwrap().contains("step 2"));
    }

    #[test]
    fn walk_does_not_loop() {
        let pki = TestPki::new();
        let back = &pki.cross_rca7_for_rca1;
        let json = roots_json(&[
            Entry {
                cert: &pki.rca1,
                prev: None,
                next: Some(&pki.cross_rca1_for_rca7),
            },
            Entry {
                cert: &pki.rca7,
                prev: None,
                next: Some(back),
            },
        ]);
        let result = walk(&pki.rca1, &parse(&json).unwrap(), NOW, DEFAULT).unwrap();
        assert_eq!(result.trusted.len(), 2);
        assert!(result.forward_stop.unwrap().contains("loops back"));
    }

    #[test]
    fn anchor_must_be_in_roots_json() {
        let pki = TestPki::new();
        let json = roots_json(&[Entry {
            cert: &pki.rca7,
            prev: None,
            next: None,
        }]);
        assert!(matches!(
            walk(&pki.rca1, &parse(&json).unwrap(), NOW, DEFAULT),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn both_document_forms_and_bad_input() {
        let pki = TestPki::new();
        let array = roots_json(&[Entry {
            cert: &pki.rca1,
            prev: None,
            next: None,
        }]);
        let object = format!(
            r#"{{"roots": {}}}"#,
            String::from_utf8(array.clone()).unwrap()
        );
        assert_eq!(parse(&array).unwrap().len(), 1);
        assert_eq!(parse(object.as_bytes()).unwrap().len(), 1);
        for bad in [
            &b"[]"[..],
            b"{}",
            b"not json",
            br#"[{"cert": "AAAA", "cn": "x"}]"#,
        ] {
            assert!(
                matches!(parse(bad), Err(Error::Malformed { .. })),
                "{bad:?}"
            );
        }
    }

    /// A date inside the validity of the real cross certificates (2026-06-01).
    const REAL_NOW: Timestamp = Timestamp(1_780_272_000);

    #[cfg(feature = "rsa")]
    #[test]
    fn embedded_prod_roots_walk_from_gem_rca7() {
        // The roots `go/gempki` trusts from the same roots.json (it walks from GEM.RCA8):
        // the anchor, then forwards, then backwards.
        let result = load(&TrustConfig::preset_prod(), REAL_NOW).unwrap();
        assert_eq!(
            cns(&result.trusted),
            [
                "GEM.RCA7",
                "GEM.RCA8",
                "GEM.RCA9",
                "GEM.RCA10",
                "GEM.RCA11",
                "GEM.RCA6",
                "GEM.RCA5",
                "GEM.RCA4",
                "GEM.RCA3",
                "GEM.RCA2",
            ]
        );
        assert_eq!((result.forward_stop, result.backward_stop), (None, None));
    }

    #[cfg(not(feature = "rsa"))]
    #[test]
    fn embedded_prod_roots_without_rsa_stop_at_the_rsa_roots() {
        let result = load(&TrustConfig::preset_prod(), REAL_NOW).unwrap();
        assert_eq!(cns(&result.trusted), ["GEM.RCA7", "GEM.RCA8"]);
        assert!(result.forward_stop.unwrap().contains("GEM.RCA9"));
        assert!(result.backward_stop.unwrap().contains("GEM.RCA6"));
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn without_brainpool_the_walk_ends_at_the_first_brainpool_root() {
        // GEM.RCA8 and GEM.RCA5 are brainpool: their self-signatures do not verify, so
        // neither they nor anything past them is trusted.
        let config = TrustConfig {
            algorithms: std::borrow::Cow::Borrowed(crate::algorithms::NIST),
            ..TrustConfig::preset_prod()
        };
        let result = load(&config, REAL_NOW).unwrap();
        assert_eq!(cns(&result.trusted), ["GEM.RCA7", "GEM.RCA6"]);
        assert!(result.forward_stop.unwrap().contains("GEM.RCA8"));
        assert!(result.backward_stop.unwrap().contains("GEM.RCA5"));
    }

    #[cfg(feature = "dangerous-nonprod")]
    #[test]
    fn embedded_nonprod_roots_contain_their_anchor() {
        use crate::Env;
        for (env, anchor) in [
            (Env::Test, "GEM.RCA7 TEST-ONLY"),
            (Env::Ref, "GEM.RCA7 TEST-ONLY"),
            (Env::Dev, "GEM.RCA7 TEST-ONLY"),
        ] {
            let store = load(&TrustConfig::preset(env), REAL_NOW).unwrap().store();
            assert!(store.by_common_name(anchor).is_some(), "{env}");
        }
    }

    #[test]
    fn config_without_roots_json_trusts_the_anchor_alone() {
        let config = TrustConfig::for_anchor(crate::anchors::GEM_RCA7);
        let result = load(&config, REAL_NOW).unwrap();
        assert_eq!(cns(&result.trusted), ["GEM.RCA7"]);
    }
}
