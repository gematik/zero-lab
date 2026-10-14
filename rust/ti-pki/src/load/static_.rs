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

//! [`StaticLoader`] and [`Bundle`]: trust material fixed at construction, for offline
//! and air-gapped deployments or as the last fallback.
//!
//! A bundle is a JSON file holding both artefacts with their metadata. It is not signed
//! and needs no signature: its contents are verified on import like any other load, and
//! the bundle only contributes `fetched_at` to the freshness policy. It records the
//! SHA-256 of the anchor it was exported for, so a bundle for another environment is
//! rejected before verification with a clear error.

use core::fmt::Write as _;
use core::time::Duration;

use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::artifact::{Artifact, TrustMaterial};
use super::loader::{Fetched, LoadError, Loaded, Loader};
use crate::TrustConfig;
use crate::time::Timestamp;
use ti_cache::{Conditional, Meta, Source};

const FORMAT_VERSION: u32 = 2;

/// Serves one fixed [`TrustMaterial`].
#[derive(Clone, Debug)]
pub struct StaticLoader {
    material: TrustMaterial,
}

impl StaticLoader {
    /// Serves `material` as it is.
    pub fn new(material: TrustMaterial) -> Self {
        StaticLoader { material }
    }

    /// Serves a bundle's material, marked as [`Source::Bundle`].
    ///
    /// # Errors
    ///
    /// [`LoadError::Bundle`] if the bundle was exported for a different anchor than
    /// `config`'s.
    pub fn from_bundle(bundle: Bundle, config: &TrustConfig) -> Result<Self, LoadError> {
        bundle.check_anchor(config)?;
        let mut material = bundle.material;
        for meta in &mut material.meta {
            meta.source = Source::Bundle;
        }
        Ok(StaticLoader { material })
    }
}

impl Loader for StaticLoader {
    async fn fetch(&self, artifact: Artifact, cond: Conditional<'_>) -> Result<Fetched, LoadError> {
        let meta = self.material.meta(artifact).clone();
        if cond.etag.is_some() && cond.etag == meta.etag.as_deref() {
            return Ok(Fetched::NotModified(meta));
        }
        Ok(Fetched::Body(Loaded {
            body: self.material.body(artifact).to_vec(),
            meta,
            stale: None,
        }))
    }
}

/// Offline trust material: both artefacts, their metadata, and the anchor they belong to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// Free-form description, e.g. the environment and export date. Not interpreted.
    pub label: String,
    /// SHA-256 of the DER anchor the material was exported for.
    pub anchor_sha256: [u8; 32],
    /// The artefacts.
    pub material: TrustMaterial,
}

impl Bundle {
    /// A bundle of `material` for `config`'s anchor.
    pub fn new(config: &TrustConfig, label: impl Into<String>, material: TrustMaterial) -> Self {
        Bundle {
            label: label.into(),
            anchor_sha256: Sha256::digest(&config.anchor).into(),
            material,
        }
    }

    /// Checks that the bundle was exported for `config`'s anchor.
    ///
    /// # Errors
    ///
    /// [`LoadError::Bundle`] on a mismatch.
    pub fn check_anchor(&self, config: &TrustConfig) -> Result<(), LoadError> {
        let expected: [u8; 32] = Sha256::digest(&config.anchor).into();
        if self.anchor_sha256 == expected {
            Ok(())
        } else {
            Err(LoadError::Bundle(format!(
                "bundle {:?} belongs to a different trust anchor",
                self.label
            )))
        }
    }

    /// The JSON encoding.
    ///
    /// # Panics
    ///
    /// Never: the wire form has only string keys and plain values.
    pub fn to_vec(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&Wire::from(self)).expect("the wire form always serialises")
    }

    /// Decodes a bundle.
    ///
    /// # Errors
    ///
    /// [`LoadError::Bundle`] if `bytes` are not a version-2 bundle.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LoadError> {
        let wire: Wire =
            serde_json::from_slice(bytes).map_err(|e| LoadError::Bundle(e.to_string()))?;
        wire.try_into().map_err(LoadError::Bundle)
    }

    /// Writes the bundle to `path`.
    ///
    /// # Errors
    ///
    /// The I/O error.
    #[cfg(feature = "os")]
    pub fn write(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::write(path, self.to_vec())
    }

    /// Reads a bundle from `path`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Bundle`] if the file cannot be read or decoded.
    #[cfg(feature = "os")]
    pub fn read(path: impl AsRef<std::path::Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| LoadError::Bundle(format!("{}: {e}", path.display())))?;
        Self::from_slice(&bytes)
    }
}

// Bodies are base64 rather than embedded strings: the TSL is XML with its own encoding
// declaration, and roots.json must come back byte for byte for its signature.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format_version: u32,
    label: String,
    anchor_sha256: String,
    roots: String,
    tsl: String,
    roots_meta: WireMeta,
    tsl_meta: WireMeta,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: u64,
    max_age_secs: Option<u64>,
    source: String,
}

impl From<&Bundle> for Wire {
    fn from(b: &Bundle) -> Self {
        let [roots_meta, tsl_meta] = b.material.meta.each_ref().map(WireMeta::from);
        Wire {
            format_version: FORMAT_VERSION,
            label: b.label.clone(),
            anchor_sha256: hex(&b.anchor_sha256),
            roots: Base64::encode_string(&b.material.roots),
            tsl: Base64::encode_string(&b.material.tsl),
            roots_meta,
            tsl_meta,
        }
    }
}

impl TryFrom<Wire> for Bundle {
    type Error = String;

    fn try_from(w: Wire) -> Result<Self, String> {
        if w.format_version != FORMAT_VERSION {
            return Err(format!(
                "unsupported bundle format version {}",
                w.format_version
            ));
        }
        let body = |name: &str, s: &str| Base64::decode_vec(s).map_err(|e| format!("{name}: {e}"));
        Ok(Bundle {
            label: w.label,
            anchor_sha256: unhex(&w.anchor_sha256).ok_or("anchor_sha256 must be 64 hex digits")?,
            material: TrustMaterial::new(
                body("roots", &w.roots)?,
                w.roots_meta.try_into()?,
                body("tsl", &w.tsl)?,
                w.tsl_meta.try_into()?,
            ),
        })
    }
}

impl From<&Meta> for WireMeta {
    fn from(m: &Meta) -> Self {
        WireMeta {
            etag: m.etag.clone(),
            last_modified: m.last_modified.clone(),
            fetched_at: m.fetched_at.0,
            max_age_secs: m.max_age.map(|age| age.as_secs()),
            source: source_name(m.source).to_owned(),
        }
    }
}

impl TryFrom<WireMeta> for Meta {
    type Error = String;

    fn try_from(w: WireMeta) -> Result<Self, String> {
        Ok(Meta {
            etag: w.etag,
            last_modified: w.last_modified,
            fetched_at: Timestamp(w.fetched_at),
            max_age: w.max_age_secs.map(Duration::from_secs),
            source: source_from_name(&w.source)?,
        })
    }
}

// Hex, not base64, so that operators can compare it with `shasum -a 256` of the anchor.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0_u8; 32];
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::Http => "http",
        Source::File => "file",
        Source::Cache => "cache",
        Source::Embedded => "embedded",
        // Also any source added to ti-cache after this format: informational only, and
        // read back from here the body did come from a bundle.
        _ => "bundle",
    }
}

fn source_from_name(name: &str) -> Result<Source, String> {
    Ok(match name {
        "http" => Source::Http,
        "file" => Source::File,
        "bundle" => Source::Bundle,
        "cache" => Source::Cache,
        "embedded" => Source::Embedded,
        _ => return Err(format!("unknown source {name:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Bundle {
        let meta = |etag: &str| Meta {
            etag: Some(etag.into()),
            last_modified: Some("Tue, 22 Sep 2026 10:00:00 GMT".into()),
            fetched_at: Timestamp(1_000),
            max_age: Some(Duration::from_secs(3600)),
            source: Source::Http,
        };
        let material = TrustMaterial::new(b"roots".to_vec(), meta("r"), b"tsl".to_vec(), meta("t"));
        Bundle::new(&TrustConfig::preset_prod(), "prod 2026-09-22", material)
    }

    #[test]
    fn json_round_trip() {
        let original = bundle();
        assert_eq!(Bundle::from_slice(&original.to_vec()).unwrap(), original);
    }

    #[cfg(feature = "os")]
    #[test]
    fn file_round_trip() {
        let path = std::env::temp_dir().join(format!("ti-pki-bundle-{}.json", std::process::id()));
        let original = bundle();
        original.write(&path).unwrap();
        let read = Bundle::read(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read.unwrap(), original);
    }

    #[test]
    fn garbage_and_other_versions_are_rejected() {
        assert!(Bundle::from_slice(b"not json").is_err());
        let mut wire = Wire::from(&bundle());
        wire.format_version = 1;
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(matches!(
            Bundle::from_slice(&bytes),
            Err(LoadError::Bundle(_))
        ));
        let mut wire = Wire::from(&bundle());
        wire.anchor_sha256.pop();
        let bytes = serde_json::to_vec(&wire).unwrap();
        assert!(Bundle::from_slice(&bytes).is_err());
    }

    #[test]
    fn bundle_for_another_anchor_is_rejected() {
        let other = TrustConfig::for_anchor(vec![0_u8; 8]);
        assert!(matches!(
            StaticLoader::from_bundle(bundle(), &other),
            Err(LoadError::Bundle(_))
        ));
        let loader = StaticLoader::from_bundle(bundle(), &TrustConfig::preset_prod()).unwrap();
        assert_eq!(loader.material.meta[1].source, Source::Bundle);
    }
}
