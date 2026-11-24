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

//! Decoding pinned against the Go implementation: every fixture (pinned by SHA-256 below)
//! decodes to the certificates, keys, attributes and pairs `go/pkcs12` reports in
//! `fixtures/go-baseline.json`, which `fixtures/generate_test_data.sh` writes. For the two BER
//! vendor files the attributes are also pinned to what `openssl pkcs12 -info` shows, a source
//! independent of both decoders.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use ti_pkcs12::{Error, decode, is_pkcs12};

/// The fixtures `generate_test_data.sh` writes from the keys of `go/pkcs12/testdata`, the vendor
/// files of `go/pkcs12/legacy/testdata`, and the generator itself.
const FIXTURES: &[(&str, &str)] = &[
    (
        "aes128.p12",
        "807e014ae52423cb5eb1be27717935b6bf815f5a295f87671932e4562589c629",
    ),
    (
        "ca-cert.pem",
        "db0d78ab94c788852905f7b425208a41ceb92058e921fbf4721a2050570393ff",
    ),
    (
        "cert-only.p12",
        "c70c0a1c4dfcc71ea04aa4da1bc2441615c3b1930a86068ece9db6f25482a012",
    ),
    (
        "chain.pem",
        "344c8c41a2e66f57b5e0de3c81a53c899aa47bfa00514b085f36033df4b127ee",
    ),
    (
        "ec-cert.pem",
        "a117dbd871475d97b81fe67bd271c56d49e0510407dd257b99f3b44007822818",
    ),
    (
        "ec.p12",
        "309d4c49a390eaa49a580fc5ab87e5ba377846f596e8e575e01843ce0fd7bd0e",
    ),
    (
        "empty-pass.p12",
        "d5f75a4ef9a3196be9b70d04b5b6151a740cbf67f7049d143f87d836aa28146d",
    ),
    (
        "generate_test_data.sh",
        "1316f76de3e94818f1fadad1ea3bb409fe276ccd951d9d37e26c444577e4aeb4",
    ),
    (
        "high-iter.p12",
        "56874c3e902e3ad08011038777f64db9ecead4c50239113503078ef804ca692c",
    ),
    (
        "legacy.p12",
        "46b3c513a446397b6a28b8794ae66a79a285a9ccb1f03ee613804e1aec8dd2c5",
    ),
    (
        "legacy/cgm-password.txt",
        "f63c8a3d6660774abced7248b6a090ff7bec841067fd58fb4a18b8f924802abf",
    ),
    (
        "legacy/cgm.p12",
        "53f7b67a82d9d5f3234ae34ee303846a3b5ef83d6765abb302e9c789dedd50c8",
    ),
    (
        "legacy/secunet-password.txt",
        "d9b2aefb1febe2dd6e403f634e18917a8c0dd1a440c976e9fe126b465ae9fc8d",
    ),
    (
        "legacy/secunet.p12",
        "4e491ea0a3847366b817d3c4696782ba49a19a51875c6b68519ebbf1632aa664",
    ),
    (
        "modern.p12",
        "9e1f9224defbdcaaa273f87617e9b89aa1383039112ef5967f0201a617e8a5ea",
    ),
    (
        "multi-cert.p12",
        "e3630a95e57c9e1939b32c4f4f227ea635ed02938d8be1124e21e1fc8a59b5c2",
    ),
    (
        "no-mac.p12",
        "2558fbf4726263fa75280f038f2196eb3268729663906f6f972e40c762da907e",
    ),
    (
        "not-pkcs12.p12",
        "cfd862bab05190c07cffdda4c093654c6532326b62c0b5234fad8647f0e052f6",
    ),
    (
        "random.p12",
        "19aee46bebe8d6dd0c30e1727f8d6d739a6e1fa9f0f44459c419be15420adeb5",
    ),
    (
        "README.md",
        "3e8b4eaa966b96422f28566a623ee3364f051e2b10ee4cf27b12aa33bb32e7ce",
    ),
    (
        "server-cert.pem",
        "cfd862bab05190c07cffdda4c093654c6532326b62c0b5234fad8647f0e052f6",
    ),
    (
        "truncated.p12",
        "ea87f2758f5a106e3c84e60e54074894705e392dfb60bb7f96dee50b7cab9fb0",
    ),
];

/// The fixtures encrypted with a PBE of RFC 7292 Appendix C (3DES, RC2), as `openssl pkcs12
/// -info` shows them: only the legacy feature reads them.
const LEGACY_ENCRYPTED: &[&str] = &["legacy.p12", "legacy/cgm.p12", "legacy/secunet.p12"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        write!(out, "{b:02x}").unwrap();
        out
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The password Go's tests use for a fixture.
fn password(file: &Path) -> String {
    let beside = file.with_file_name(format!(
        "{}-password.txt",
        file.file_stem().unwrap().to_str().unwrap()
    ));
    if let Ok(password) = std::fs::read_to_string(beside) {
        return password.trim().to_owned();
    }
    if file.ends_with("empty-pass.p12") {
        String::new()
    } else {
        "test1234".to_owned()
    }
}

/// The fixtures are pinned: a test of the test data, no rule.
#[test]
fn fixtures_are_the_go_ones() {
    for (name, expected) in FIXTURES {
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        assert_eq!(&sha256(&bytes), expected, "{name} changed");
    }
}

/// Interoperability with `go/pkcs12`: every fixture yields what Go's decoder reports.
/// Covers the bag rules (P12-040 to P12-046) as a whole, not each rule.
#[test]
fn decodes_like_go() {
    let baseline: Value =
        serde_json::from_slice(&std::fs::read(fixtures().join("go-baseline.json")).unwrap())
            .unwrap();
    for entry in baseline.as_array().unwrap() {
        let name = entry["file"].as_str().unwrap();
        let path = fixtures().join(name);
        let bytes = std::fs::read(&path).unwrap();
        let result = decode(&bytes, &password(&path));
        if entry.get("error").is_some() {
            assert!(
                matches!(result, Err(Error::Malformed { .. })),
                "{name}: Go failed, Rust gave {result:?}"
            );
            assert!(!is_pkcs12(&bytes) || name == "truncated.p12", "{name}");
            continue;
        }
        if !cfg!(feature = "legacy") && LEGACY_ENCRYPTED.contains(&name) {
            assert!(
                matches!(result, Err(Error::UnsupportedAlgorithm(_))),
                "{name}: without the legacy feature, Rust gave {result:?}"
            );
            continue;
        }
        let p12 = result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(is_pkcs12(&bytes), "{name}");

        let comparable = |mut bag: Value| {
            bag.as_object_mut().unwrap().remove("subject");
            bag
        };
        let certificates: Vec<Value> = p12
            .certificates
            .iter()
            .map(|c| {
                comparable(serde_json::json!({
                    "friendly_name": c.friendly_name.clone().unwrap_or_default(),
                    "local_key_id": hex(c.local_key_id.as_deref().unwrap_or_default()),
                    "sha256": sha256(&c.der),
                }))
            })
            .collect();
        let expected: Vec<Value> = entry["certificates"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(comparable)
            .collect();
        assert_eq!(certificates, expected, "{name}: certificates");

        let keys: Vec<Value> = p12
            .keys
            .iter()
            .map(|k| {
                comparable(serde_json::json!({
                    "friendly_name": k.friendly_name.clone().unwrap_or_default(),
                    "local_key_id": hex(k.local_key_id.as_deref().unwrap_or_default()),
                    "sha256": sha256(&k.pkcs8),
                }))
            })
            .collect();
        let expected: Vec<Value> = entry["keys"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .map(comparable)
            .collect();
        assert_eq!(keys, expected, "{name}: keys");
        assert_eq!(
            p12.pairs().len(),
            usize::try_from(entry["pairs"].as_u64().unwrap()).unwrap(),
            "{name}: pairs"
        );
    }
}

/// A wrong password fails the MAC; without a MAC (P12-015) only the padding check of
/// P12-034 notices it.
#[test]
fn p12_010_wrong_passwords_are_told_apart_from_broken_files() {
    let read = |name: &str| std::fs::read(fixtures().join(name)).unwrap();
    assert!(matches!(
        decode(&read("modern.p12"), "wrong"),
        Err(Error::MacMismatch)
    ));
    assert!(matches!(
        decode(&read("legacy/cgm.p12"), "00"),
        Err(Error::MacMismatch)
    ));
    // Without a MAC, only the padding of the decryption notices.
    assert!(matches!(
        decode(&read("no-mac.p12"), "wrong"),
        Err(Error::DecryptFailed)
    ));
    for (name, password) in [("modern.p12", "wrong"), ("no-mac.p12", "wrong")] {
        let err = decode(&read(name), password).unwrap_err();
        assert!(err.is_wrong_password(), "{name}: {err}");
    }
    for name in ["truncated.p12", "not-pkcs12.p12"] {
        let err = decode(&read(name), "test1234").unwrap_err();
        assert!(!err.is_wrong_password(), "{name}: {err}");
    }
}

/// P12-036: a file whose producer chose high iteration counts opens while its derivations (the
/// MAC, and PBKDF2 for the certificates and for the key) stay within the work budget of one
/// decode. `high-iter.p12` has 600,000 for each, 1,800,000 of 10,000,000.
#[test]
fn p12_036_high_iteration_counts_within_the_budget_are_decoded() {
    const HIGH_ITERATIONS: u32 = 600_000;
    const { assert!(HIGH_ITERATIONS * 3 <= ti_pkcs12::MAX_ITERATIONS) };
    let bytes = std::fs::read(fixtures().join("high-iter.p12")).unwrap();
    let p12 = decode(&bytes, "test1234").unwrap();
    assert_eq!(p12.pairs().len(), 1);
    assert_eq!(p12.mac.unwrap().iterations, HIGH_ITERATIONS);
}

/// `is_pkcs12` tells a PFX from other input by its first bytes, under a length of
/// any form: short, long, or BER's indefinite one.
#[test]
fn is_pkcs12_reads_every_length_form() {
    let version_3 = [0x02, 0x01, 0x03];
    let pfx = |length: &[u8]| [&[0x30][..], length, &version_3].concat();
    assert!(is_pkcs12(&pfx(&[0x05])), "short");
    assert!(is_pkcs12(&pfx(&[0x81, 0x90])), "long");
    assert!(is_pkcs12(&pfx(&[0x80])), "indefinite");
    assert!(!is_pkcs12(&[0x30, 0x05, 0x02, 0x01, 0x02]), "version 2");
}

/// What a file is protected with is reported: an API property, no rule.
#[test]
fn reports_mac_and_encryption() {
    let read = |name: &str| std::fs::read(fixtures().join(name)).unwrap();
    let modern = decode(&read("modern.p12"), "test1234").unwrap();
    let mac = modern.mac.unwrap();
    assert_eq!((mac.digest.as_str(), mac.iterations), ("SHA-256", 2048));
    assert!(
        modern
            .encryption
            .iter()
            .all(|e| e.algorithm == "PBES2 AES-256-CBC")
    );

    if !cfg!(feature = "legacy") {
        return;
    }
    let path = fixtures().join("legacy/cgm.p12");
    let vendor = decode(&std::fs::read(&path).unwrap(), &password(&path)).unwrap();
    assert_eq!(vendor.mac.unwrap().iterations, 102_400);
    let used = |target, algorithm: &str| {
        vendor.encryption.contains(&ti_pkcs12::Encryption {
            target,
            algorithm: algorithm.to_owned(),
        })
    };
    assert!(
        used(ti_pkcs12::Target::Safe, "PKCS#12 RC2-40"),
        "certificates"
    );
    assert!(used(ti_pkcs12::Target::Key, "PKCS#12 3DES"), "key");

    let (algorithm, curve) = decode(&read("ec.p12"), "test1234").unwrap().keys[0]
        .algorithm()
        .unwrap();
    assert_eq!(algorithm.to_string(), "1.2.840.10045.2.1", "id-ecPublicKey");
    assert_eq!(curve.unwrap().to_string(), "1.2.840.10045.3.1.7", "P-256");
}

/// The attributes of the BER vendor files as `openssl pkcs12 -info -legacy` shows them
/// in the originals: the key and its certificate share a `localKeyId` and a name, the
/// CA certificate in `cgm.p12` has none. Also P12-002 (BER) and P12-045 (pairs).
#[cfg(feature = "legacy")]
#[test]
fn p12_044_ber_files_keep_their_attributes() {
    for (name, friendly_name, local_key_id, scalar) in [
        (
            "cgm",
            "test-cs2",
            "1275112faa9c4af6c3e43a278ac902348f6bf1d1",
            "01fbee24456ac8b47f54530f8bc521e3322e2e53ea290c388762f15a53a0e758",
        ),
        (
            "secunet",
            "valid_ec",
            "8a1bc0d03fa061f52938675c1897d2f533cfae17",
            SECUNET_SCALAR,
        ),
    ] {
        let path = fixtures().join(format!("legacy/{name}.p12"));
        let p12 = decode(&std::fs::read(&path).unwrap(), &password(&path)).unwrap();
        let key = &p12.keys[0];
        assert_eq!(key.friendly_name.as_deref(), Some(friendly_name), "{name}");
        assert_eq!(
            hex(key.local_key_id.as_deref().unwrap()),
            local_key_id,
            "{name}"
        );
        // The private scalar `openssl pkey -text` prints for the key of the original file.
        assert!(hex(&key.pkcs8).contains(scalar), "{name}: key material");
        let pairs = p12.pairs();
        assert_eq!(pairs.len(), 1, "{name}");
        let certificate = &p12.certificates[pairs[0].certificate];
        assert_eq!(
            certificate.friendly_name.as_deref(),
            Some(friendly_name),
            "{name}"
        );
    }
}

/// The private scalar of the key in `legacy/secunet.p12`, as `openssl pkey -text` prints it.
#[cfg(feature = "legacy")]
const SECUNET_SCALAR: &str = "5605847b0310c128044501cbe9fb1ac4c421571097d0b4c12a0439628fca4137";

/// Without the legacy feature, a file encrypted with an RFC 7292 Appendix C PBE is refused for its
/// algorithm, never read or taken for a wrong password. A property of the crate's
/// features: the spec's `modern` profile still reads pbeWithSHAAnd3-KeyTripleDES-CBC.
#[cfg(not(feature = "legacy"))]
#[test]
fn without_legacy_an_appendix_c_pbe_is_unsupported() {
    for name in LEGACY_ENCRYPTED {
        let path = fixtures().join(name);
        let result = decode(&std::fs::read(&path).unwrap(), &password(&path));
        assert!(
            matches!(result, Err(Error::UnsupportedAlgorithm(_))),
            "{name}: {result:?}"
        );
    }
}
