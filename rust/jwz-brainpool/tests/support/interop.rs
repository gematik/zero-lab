#![allow(
    dead_code,
    reason = "shared by the generator and the test, each uses a part"
)]

//! Brainpool interoperability fixtures (`tests/data/interop`), shared by the generator
//! (`examples/interop.rs`) and the build-time check (`tests/interop.rs`).
//!
//! - `keys.json`: the keys every implementation uses, by name.
//! - `jwz.json`: tokens jwz makes; each oracle checks them into `<oracle>-verdicts.json`,
//!   stamped with the SHA-256 of the `jwz.json` it checked.
//! - `<oracle>.json`: tokens the oracle makes, which jwz must verify.
//! - `COVERAGE.md`: both directions as a table.
//!
//! jwz's tokens are deterministic (fixed random source, RFC 6979 signatures), so the
//! build-time check regenerates them and fails when jwz's output changed and the oracles
//! have not checked the new tokens yet.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jwz::crypto::rustcrypto::RustCrypto;
use jwz::crypto::{Backend, Extended};
use jwz::header::HeaderParams;
use jwz::jwa::{
    ContentEncryptionAlgorithm as Enc, HashAlgorithm, KeyEncryptionAlgorithm as Alg, Registry,
    SignatureAlgorithm,
};
use jwz::jwe::json::Recipient;
use jwz::jwe::{self, EncryptionKey};
use jwz::jwk::Jwk;
use jwz::jws::{self, Jws};
use jwz::keys::{FixedRng, Signer, SoftwareKey, Verifier};
use jwz::profile::Profile;
use jwz_brainpool::{BP256R1, BrainpoolEs256Key};
use serde_json::{Value, json};

/// The oracles, in the order of the coverage table.
pub const ORACLES: &[&str] = &["go", "python"];

/// ePA's key: `ES256` on brainpoolP256r1.
pub const ES256_BRAINPOOL: &str = "es256-bp";

const SEED: u64 = 0x6a77_7a2d_6270_3235;

/// One token and what it carries.
#[derive(Clone, Debug, PartialEq)]
pub struct Case {
    pub id: String,
    /// `jws` or `jwe`.
    pub kind: String,
    /// `compact`, `general` or `flattened`.
    pub serialization: String,
    /// The `alg` per signature or recipient.
    pub algs: Vec<String>,
    pub enc: Option<String>,
    /// The key per signature or recipient, by name in `keys.json`.
    pub keys: Vec<String>,
    pub payload: String,
    /// The compact form, or the JSON serialization as text.
    pub token: String,
}

impl Case {
    pub fn from_json(value: &Value) -> Result<Case, String> {
        let text = |name: &str| {
            value[name]
                .as_str()
                .map(String::from)
                .ok_or_else(|| format!("case member {name}"))
        };
        let list = |name: &str| -> Result<Vec<String>, String> {
            value[name]
                .as_array()
                .ok_or_else(|| format!("case member {name}"))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .ok_or_else(|| format!("case member {name}"))
                })
                .collect()
        };
        Ok(Case {
            id: text("id")?,
            kind: text("kind")?,
            serialization: text("serialization")?,
            algs: list("algs")?,
            enc: value["enc"].as_str().map(String::from),
            keys: list("keys")?,
            payload: text("payload")?,
            token: text("token")?,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut object = json!({
            "id": self.id,
            "kind": self.kind,
            "serialization": self.serialization,
            "algs": self.algs,
            "keys": self.keys,
            "payload": self.payload,
            "token": self.token,
        });
        if let Some(enc) = &self.enc {
            object["enc"] = json!(enc);
        }
        object
    }
}

pub fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/interop")
}

pub fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
}

/// The library and cases of a tokens file.
pub fn read_cases(path: &Path) -> Result<(String, Vec<Case>), String> {
    let file = read_json(path)?;
    let library = file["library"].as_str().unwrap_or("unknown").to_string();
    let cases = file["cases"]
        .as_array()
        .ok_or_else(|| format!("{}: no cases", path.display()))?
        .iter()
        .map(Case::from_json)
        .collect::<Result<_, _>>()?;
    Ok((library, cases))
}

pub fn read_keys(path: &Path) -> Result<BTreeMap<String, Jwk>, String> {
    let file = read_json(path)?;
    file.as_object()
        .ok_or("keys.json is not an object")?
        .iter()
        .map(|(name, jwk)| {
            Jwk::parse(&jwk.to_string())
                .map(|jwk| (name.clone(), jwk))
                .map_err(|e| format!("key {name}: {e}"))
        })
        .collect()
}

/// The canonical payload: what josebp's and jwcrypto's JSON encoders produce too.
pub fn payload(id: &str) -> String {
    json!({"case": id, "iss": "jwz-interop"}).to_string()
}

/// RustCrypto plus BP-256 on a fixed random source: the same tokens on every run.
pub fn deterministic_backend() -> Arc<Extended<RustCrypto>> {
    Arc::new(jwz_brainpool::backend(RustCrypto::with_rng(Box::new(
        FixedRng::new(SEED),
    ))))
}

fn signature_algorithm(key: &str) -> SignatureAlgorithm {
    if key == ES256_BRAINPOOL {
        SignatureAlgorithm::ES256
    } else {
        BP256R1
    }
}

fn signer(
    name: &str,
    keys: &BTreeMap<String, Jwk>,
    registry: &Registry,
    backend: &Arc<Extended<RustCrypto>>,
) -> Result<Box<dyn Signer>, String> {
    let jwk = keys.get(name).ok_or_else(|| format!("no key {name}"))?;
    if name == ES256_BRAINPOOL {
        return BrainpoolEs256Key::from_jwk(jwk)
            .map(|k| Box::new(k) as Box<dyn Signer>)
            .map_err(|e| e.to_string());
    }
    SoftwareKey::from_jwk(jwk, BP256R1, registry, Arc::clone(backend))
        .map(|k| Box::new(k.with_kid(name)) as Box<dyn Signer>)
        .map_err(|e| e.to_string())
}

fn verifier(
    name: &str,
    keys: &BTreeMap<String, Jwk>,
    registry: &Registry,
    backend: &Arc<Extended<RustCrypto>>,
) -> Result<Box<dyn Verifier>, String> {
    let jwk = keys.get(name).ok_or_else(|| format!("no key {name}"))?;
    if name == ES256_BRAINPOOL {
        return BrainpoolEs256Key::from_jwk(&jwk.public())
            .map(|k| Box::new(k.with_kid(name)) as Box<dyn Verifier>)
            .map_err(|e| e.to_string());
    }
    SoftwareKey::from_jwk(&jwk.public(), BP256R1, registry, Arc::clone(backend))
        .map(|k| Box::new(k.with_kid(name)) as Box<dyn Verifier>)
        .map_err(|e| e.to_string())
}

/// Verifies a JWS case with jwz under `ti_legacy`-like policy (BP256R1 and ES256) and
/// checks its payload. Brainpool JWE is not decrypted by jwz yet.
pub fn verify_with_jwz(case: &Case, keys: &BTreeMap<String, Jwk>) -> Result<(), String> {
    if case.kind != "jws" {
        return Err(format!("{}: jwz does not decrypt brainpool JWE", case.id));
    }
    let registry = jwz_brainpool::registry();
    let backend = Arc::new(jwz_brainpool::backend(RustCrypto::new()));
    let mut policy = Profile::strict().policy;
    policy.signature_algorithms.push(BP256R1);
    let all = if case.serialization == "compact" {
        vec![Jws::parse(&case.token, &policy, &registry).map_err(|e| format!("parse: {e}"))?]
    } else {
        jws::json::parse(&case.token, &policy, &registry).map_err(|e| format!("parse: {e}"))?
    };
    if all.len() != case.keys.len() {
        return Err(format!(
            "{} signatures, {} keys",
            all.len(),
            case.keys.len()
        ));
    }
    for (jws, name) in all.into_iter().zip(&case.keys) {
        let key = verifier(name, keys, &registry, &backend)?;
        let verified = jws
            .verify(key.as_ref())
            .map_err(|e| format!("verify with {name}: {e}"))?;
        if verified.payload() != case.payload.as_bytes() {
            return Err("payload differs".into());
        }
    }
    Ok(())
}

/// jwz's tokens for the oracles, from `keys`.
pub fn jwz_cases(keys: &BTreeMap<String, Jwk>) -> Result<Vec<Case>, String> {
    let registry = jwz_brainpool::registry();
    let backend = deterministic_backend();
    let mut cases = jws_cases(keys, &registry, &backend)?;
    for case in &cases {
        verify_with_jwz(case, keys).map_err(|e| format!("{}: {e}", case.id))?;
    }
    cases.extend(jwe_cases(keys, &registry, &backend)?);
    Ok(cases)
}

fn jws_cases(
    keys: &BTreeMap<String, Jwk>,
    registry: &Registry,
    backend: &Arc<Extended<RustCrypto>>,
) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    for (id, key) in [
        ("jws-compact-BP256R1", "bp256r1"),
        ("jws-compact-ES256-brainpool", ES256_BRAINPOOL),
    ] {
        let signer = signer(key, keys, registry, backend)?;
        let token = jws::sign(
            payload(id).as_bytes(),
            HeaderParams::new().typ("JWT"),
            signer.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        cases.push(Case {
            id: id.into(),
            kind: "jws".into(),
            serialization: "compact".into(),
            algs: vec![signature_algorithm(key).as_str().into()],
            enc: None,
            keys: vec![key.into()],
            payload: payload(id),
            token,
        });
    }

    for (id, names, flattened) in [
        ("jws-flattened-BP256R1", &["bp256r1"][..], true),
        (
            "jws-general-BP256R1+BP256R1",
            &["bp256r1", "bp256r1"][..],
            false,
        ),
    ] {
        let signers = names
            .iter()
            .map(|n| signer(n, keys, registry, backend))
            .collect::<Result<Vec<_>, _>>()?;
        let pairs: Vec<(&dyn Signer, HeaderParams)> = signers
            .iter()
            .map(|s| (s.as_ref(), HeaderParams::new()))
            .collect();
        let general = jws::json::sign(payload(id).as_bytes(), &pairs).map_err(|e| e.to_string())?;
        cases.push(Case {
            id: id.into(),
            kind: "jws".into(),
            serialization: if flattened { "flattened" } else { "general" }.into(),
            algs: vec![BP256R1.as_str().into(); names.len()],
            enc: None,
            keys: names.iter().map(|n| (*n).to_string()).collect(),
            payload: payload(id),
            token: if flattened {
                flatten(&general, "signatures")?
            } else {
                general
            },
        });
    }
    Ok(cases)
}

/// Encryption to the IDP-like `ecdh-bp256` key: the oracles decrypt, jwz does not yet.
fn jwe_cases(
    keys: &BTreeMap<String, Jwk>,
    registry: &Registry,
    backend: &Arc<Extended<RustCrypto>>,
) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    let idp_enc = keys.get("ecdh-bp256").ok_or("no key ecdh-bp256")?.public();
    for alg in [Alg::ECDH_ES, Alg::ECDH_ES_A256KW] {
        let id = format!("jwe-compact-{}-A256GCM", alg.as_str());
        let token = jwe::encrypt(
            payload(&id).as_bytes(),
            alg,
            Enc::A256GCM,
            EncryptionKey::Public(&idp_enc),
            HeaderParams::new(),
            registry,
            backend.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        cases.push(Case {
            id: id.clone(),
            kind: "jwe".into(),
            serialization: "compact".into(),
            algs: vec![alg.as_str().into()],
            enc: Some("A256GCM".into()),
            keys: vec!["ecdh-bp256".into()],
            payload: payload(&id),
            token,
        });
    }
    for (id, algs, flattened) in [
        (
            "jwe-flattened-ECDH-ES+A128KW-A256GCM",
            &[Alg::ECDH_ES_A128KW][..],
            true,
        ),
        (
            "jwe-general-ECDH-ES+A128KW+ECDH-ES+A256KW-A256GCM",
            &[Alg::ECDH_ES_A128KW, Alg::ECDH_ES_A256KW][..],
            false,
        ),
    ] {
        let recipients: Vec<Recipient<'_>> = algs
            .iter()
            .map(|alg| Recipient {
                alg: *alg,
                key: EncryptionKey::Public(&idp_enc),
                header: HeaderParams::new(),
            })
            .collect();
        let general = jwe::json::encrypt(
            payload(id).as_bytes(),
            Enc::A256GCM,
            HeaderParams::new(),
            &recipients,
            None,
            registry,
            backend.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        cases.push(Case {
            id: id.into(),
            kind: "jwe".into(),
            serialization: if flattened { "flattened" } else { "general" }.into(),
            algs: algs.iter().map(|a| a.as_str().to_string()).collect(),
            enc: Some("A256GCM".into()),
            keys: vec!["ecdh-bp256".into(); algs.len()],
            payload: payload(id),
            token: if flattened {
                flatten(&general, "recipients")?
            } else {
                general
            },
        });
    }
    Ok(cases)
}

/// RFC 7515 §7.2.2 / RFC 7516 §7.2.2: the one entry of `list` at the top level.
fn flatten(general: &str, list: &str) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(general).map_err(|e| e.to_string())?;
    let object = value.as_object_mut().ok_or("not an object")?;
    let entries = object.remove(list).ok_or("no entries")?;
    let entry = entries
        .get(0)
        .and_then(Value::as_object)
        .ok_or("no entry")?;
    for (name, member) in entry {
        object.insert(name.clone(), member.clone());
    }
    Ok(value.to_string())
}

/// The tokens file jwz writes.
pub fn jwz_file(cases: &[Case]) -> Value {
    json!({
        "library": format!("jwz {}", jwz_version()),
        "cases": cases.iter().map(Case::to_json).collect::<Vec<_>>(),
    })
}

/// jwz's version, from the lock-step workspace dependency.
fn jwz_version() -> &'static str {
    "0.1"
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let backend = RustCrypto::new();
    let digest = backend
        .hash(HashAlgorithm::Sha256)
        .map(|h| h.digest(&[bytes]))
        .unwrap_or_default();
    digest.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// An oracle's verdicts on `jwz.json`.
pub struct Verdicts {
    pub library: String,
    /// SHA-256 of the `jwz.json` it checked.
    pub source: String,
    /// `ok`, `skipped: …` or `failed: …` per case id.
    pub results: BTreeMap<String, String>,
}

pub fn read_verdicts(path: &Path) -> Result<Verdicts, String> {
    let file = read_json(path)?;
    let results = file["results"]
        .as_object()
        .ok_or_else(|| format!("{}: no results", path.display()))?
        .iter()
        .map(|(id, r)| {
            (
                id.clone(),
                r.as_str().unwrap_or("failed: not a string").to_string(),
            )
        })
        .collect();
    Ok(Verdicts {
        library: file["library"].as_str().unwrap_or("unknown").to_string(),
        source: file["source"].as_str().unwrap_or_default().to_string(),
        results,
    })
}

/// The coverage table, as committed in `COVERAGE.md`.
pub fn coverage(dir: &Path) -> Result<String, String> {
    let (_, jwz_cases) = read_cases(&dir.join("jwz.json"))?;
    let mut out = String::from(
        "# Brainpool interoperability\n\nGenerated by `just jwz-interop` from the fixtures in \
         this directory; `cargo test -p jwz-brainpool --test interop` fails if it is stale.\n\n\
         | Oracle | Library |\n| --- | --- |\n",
    );
    let mut made = Vec::new();
    let mut checked = BTreeMap::new();
    for oracle in ORACLES {
        let (library, cases) = read_cases(&dir.join(format!("{oracle}.json")))?;
        let _ = writeln!(out, "| {oracle} | {library} |");
        made.push((*oracle, cases));
        checked.insert(
            *oracle,
            read_verdicts(&dir.join(format!("{oracle}-verdicts.json")))?,
        );
    }

    out.push_str("\n## jwz's tokens, checked by each oracle\n\n| Case |");
    for oracle in ORACLES {
        let _ = write!(out, " {oracle} |");
    }
    out.push_str("\n| --- |");
    for _ in ORACLES {
        out.push_str(" --- |");
    }
    out.push('\n');
    for case in &jwz_cases {
        let _ = write!(out, "| `{}` |", case.id);
        for oracle in ORACLES {
            let cell = match checked.get(oracle).and_then(|v| v.results.get(&case.id)) {
                Some(r) if r == "ok" => "ok".to_string(),
                Some(r) => match r.strip_prefix("skipped: ") {
                    Some(reason) => format!("– ({reason})"),
                    None => format!("**{r}**"),
                },
                None => "–".to_string(),
            };
            let _ = write!(out, " {cell} |");
        }
        out.push('\n');
    }

    out.push_str(
        "\n## Each oracle's tokens, verified by jwz\n\n| Oracle | Cases |\n| --- | --- |\n",
    );
    for (oracle, cases) in &made {
        let ids: Vec<String> = cases.iter().map(|c| format!("`{}`", c.id)).collect();
        let _ = writeln!(out, "| {oracle} | {} |", ids.join(", "));
    }
    out.push_str(
        "\nBrainpool JWE goes one way: jwz encrypts, the oracles decrypt. jwz does not \
         decrypt brainpool JWE yet.\n",
    );
    Ok(out)
}
