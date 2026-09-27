//! Decoding pinned against the Go implementation: every fixture of `go/pkcs12` (copied
//! unchanged, pinned by SHA-256 below) decodes to the certificates, keys, attributes and
//! pairs Go's decoder reports in `fixtures/go-baseline.json`. Go reads the two BER
//! vendor files through an `openssl -legacy` re-export, which assigns new `localKeyId`s
//! and drops `friendlyName`; here they decode natively, so for those two the attributes
//! are pinned to what `openssl pkcs12 -info` shows in the original file instead.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use ti_pkcs12::{Error, decode, is_pkcs12};

/// The fixtures as copied from `go/pkcs12/testdata` and `go/pkcs12/legacy/testdata`.
const FIXTURES: &[(&str, &str)] = &[
    (
        "aes128.p12",
        "7e68bc88486e15b8aad1b4cedeab2faf1a3821dd83e5b47043bd52b402263fe6",
    ),
    (
        "ca-cert.pem",
        "491ba985ed2fcfb47a43fbe18578ab7b747f0435b8a1c05d1edcdff419007f56",
    ),
    (
        "cert-only.p12",
        "3ac0b55804f0b9d5bb36d53e8128dd4ccda6c95a22ed8ecba87afb1a593df1c6",
    ),
    (
        "chain.pem",
        "724d2e5f96d9565b639775150892bd60853927c36fd8cda1428c6d207abb2121",
    ),
    (
        "ec-cert.pem",
        "fc9643413db6351b12e571e89bcbff2cba3a66285382da768db48b3b28dfd5d7",
    ),
    (
        "ec.p12",
        "63a3169c8a557fbdd58427596813b1934c64a8f940c023618d8ea7d6d7e31656",
    ),
    (
        "empty-pass.p12",
        "0f6da7eed6df1115fb09dcc55c7242c8cf9e2935f1f20a63b0a484027276018f",
    ),
    (
        "generate_test_data.sh",
        "d39ca35a0d67dba134b2357bf9e0df8aa1d12c669aff77c82e31082c59eddbd6",
    ),
    (
        "high-iter.p12",
        "816fac1f39d8bf684156525f09ef852501554fcb1ebf8d2a2bfc8df279dfb552",
    ),
    (
        "legacy.p12",
        "41a32daf3536df1007b6bd12d17c0cd6ab89aa603b27c189f39338d61f082bea",
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
        "8c0d0ea06719b689ea82980c79340b894e7d7bd6ddc39eeea8377848d239a602",
    ),
    (
        "multi-cert.p12",
        "44ce70b5ce1ac46c2cf462cb2dbc35d283b1b6854e159e9931ae87b2f3fe1a3f",
    ),
    (
        "no-mac.p12",
        "de267f0ee4a916875b0e31ba5dd447318d53480ac0dd021a3ead1b814cf5cdb3",
    ),
    (
        "not-pkcs12.p12",
        "f0937bf08878010f583b16a984b95e861ecd88e2bd0198fb5e58318c14c6a3b2",
    ),
    (
        "random.p12",
        "8e9743b8c4b2e60a48e85ff1877450437f90f7aaa296d25f6d87d16c1703aa46",
    ),
    (
        "README.md",
        "8074f3d178bddd0417462eab9bcd1329f10db544a2dee9a0bca0ef823b5bbcd0",
    ),
    (
        "server-cert.pem",
        "f0937bf08878010f583b16a984b95e861ecd88e2bd0198fb5e58318c14c6a3b2",
    ),
    (
        "truncated.p12",
        "17f3172e90fc983d756d620d60fc5766c716cc8356c8f14157863f3569ea1611",
    ),
];

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

#[test]
fn fixtures_are_the_go_ones() {
    for (name, expected) in FIXTURES {
        let bytes = std::fs::read(fixtures().join(name)).unwrap();
        assert_eq!(&sha256(&bytes), expected, "{name} changed");
    }
}

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
        let p12 = result.unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(is_pkcs12(&bytes), "{name}");

        // Go's attributes for the BER files are OpenSSL's re-export, not the file's.
        let reexported = name.starts_with("legacy/");
        let comparable = |mut bag: Value| {
            let bag_fields = bag.as_object_mut().unwrap();
            bag_fields.remove("subject");
            if reexported {
                bag_fields.remove("friendly_name");
                bag_fields.remove("local_key_id");
            }
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
        // The re-export also re-encodes the PKCS#8 key (it drops the redundant curve
        // inside ECPrivateKey); the same keys are checked by their scalars below.
        if !reexported {
            assert_eq!(keys, expected, "{name}: keys");
        }
        assert_eq!(keys.len(), expected.len(), "{name}: key count");
        assert_eq!(
            p12.pairs().len(),
            usize::try_from(entry["pairs"].as_u64().unwrap()).unwrap(),
            "{name}: pairs"
        );
    }
}

#[test]
fn wrong_passwords_are_told_apart_from_broken_files() {
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
}

#[test]
fn reports_mac_and_encryption() {
    let read = |name: &str| std::fs::read(fixtures().join(name)).unwrap();
    let modern = decode(&read("modern.p12"), "test1234").unwrap();
    let mac = modern.mac.unwrap();
    assert_eq!((mac.digest.as_str(), mac.iterations), ("SHA-256", 2048));
    assert!(modern.encryption.iter().all(|e| e == "PBES2 AES-256-CBC"));

    let path = fixtures().join("legacy/cgm.p12");
    let vendor = decode(&std::fs::read(&path).unwrap(), &password(&path)).unwrap();
    assert_eq!(vendor.mac.unwrap().iterations, 102_400);
    assert!(vendor.encryption.contains(&"PKCS#12 RC2-40".to_owned()));
    assert!(vendor.encryption.contains(&"PKCS#12 3DES".to_owned()));

    let (algorithm, curve) = decode(&read("ec.p12"), "test1234").unwrap().keys[0]
        .algorithm()
        .unwrap();
    assert_eq!(algorithm.to_string(), "1.2.840.10045.2.1", "id-ecPublicKey");
    assert_eq!(curve.unwrap().to_string(), "1.2.840.10045.3.1.7", "P-256");
}

/// The attributes of the BER vendor files as `openssl pkcs12 -info -legacy` shows them
/// in the originals: the key and its certificate share a `localKeyId` and a name, the
/// CA certificate in `cgm.p12` has none.
#[test]
fn ber_files_keep_their_attributes() {
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
const SECUNET_SCALAR: &str = "5605847b0310c128044501cbe9fb1ac4c421571097d0b4c12a0439628fca4137";
