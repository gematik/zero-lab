//! [`StaticLoader`] and [`Bundle`]: trust material fixed at construction, for offline
//! and air-gapped deployments or as the last fallback.
//!
//! A bundle is a CBOR file holding both artefacts with their metadata. It is not signed
//! and needs no signature: its contents are verified on import like any other load, and
//! the bundle only contributes `fetched_at` to the freshness policy. It records the
//! SHA-256 of the anchor it was exported for, so a bundle for another environment is
//! rejected before verification with a clear error.

use core::time::Duration;

use minicbor::data::Type;
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

use super::artifact::{Artifact, TrustMaterial};
use super::loader::{Fetched, LoadError, Loaded, Loader};
use crate::TrustConfig;
use crate::time::Timestamp;
use ti_cache::{Conditional, Meta, Source};

const FORMAT_VERSION: u32 = 1;

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

    /// The CBOR encoding.
    ///
    /// # Panics
    ///
    /// Never: encoding into memory cannot fail.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        encode(&mut e, self).expect("encoding into a Vec cannot fail");
        e.into_writer()
    }

    /// Decodes a bundle.
    ///
    /// # Errors
    ///
    /// [`LoadError::Bundle`] if `bytes` are not a version-1 bundle.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LoadError> {
        decode(&mut Decoder::new(bytes)).map_err(|e| LoadError::Bundle(e.to_string()))
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

// Layout: [format_version, label, anchor_sha256, roots, tsl, roots_meta, tsl_meta]
// with meta = [etag?, last_modified?, fetched_at, max_age_secs?, source].
fn encode<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    b: &Bundle,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.array(7)?
        .u32(FORMAT_VERSION)?
        .str(&b.label)?
        .bytes(&b.anchor_sha256)?
        .bytes(&b.material.roots)?
        .bytes(&b.material.tsl)?;
    for meta in &b.material.meta {
        e.array(5)?;
        opt_str(e, meta.etag.as_deref())?;
        opt_str(e, meta.last_modified.as_deref())?;
        e.u64(meta.fetched_at.0)?;
        match meta.max_age {
            Some(age) => e.u64(age.as_secs())?,
            None => e.null()?,
        };
        e.u8(source_code(meta.source))?;
    }
    Ok(())
}

fn opt_str<W: minicbor::encode::Write>(
    e: &mut Encoder<W>,
    s: Option<&str>,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    match s {
        Some(s) => e.str(s)?,
        None => e.null()?,
    };
    Ok(())
}

fn decode(d: &mut Decoder<'_>) -> Result<Bundle, minicbor::decode::Error> {
    expect_array(d, 7)?;
    let version = d.u32()?;
    if version != FORMAT_VERSION {
        return Err(minicbor::decode::Error::message(
            "unsupported bundle format version",
        ));
    }
    let label = d.str()?.to_owned();
    let anchor_sha256 = d
        .bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("anchor hash must be 32 bytes"))?;
    let roots = d.bytes()?.to_vec();
    let tsl = d.bytes()?.to_vec();
    let roots_meta = decode_meta(d)?;
    let tsl_meta = decode_meta(d)?;
    Ok(Bundle {
        label,
        anchor_sha256,
        material: TrustMaterial::new(roots, roots_meta, tsl, tsl_meta),
    })
}

fn decode_meta(d: &mut Decoder<'_>) -> Result<Meta, minicbor::decode::Error> {
    expect_array(d, 5)?;
    let etag = opt_string(d)?;
    let last_modified = opt_string(d)?;
    let fetched_at = Timestamp(d.u64()?);
    let max_age = if d.datatype()? == Type::Null {
        d.null()?;
        None
    } else {
        Some(Duration::from_secs(d.u64()?))
    };
    let source = source_from_code(d.u8()?)?;
    Ok(Meta {
        etag,
        last_modified,
        fetched_at,
        max_age,
        source,
    })
}

fn expect_array(d: &mut Decoder<'_>, len: u64) -> Result<(), minicbor::decode::Error> {
    if d.array()? == Some(len) {
        Ok(())
    } else {
        Err(minicbor::decode::Error::message(
            "unexpected bundle structure",
        ))
    }
}

fn opt_string(d: &mut Decoder<'_>) -> Result<Option<String>, minicbor::decode::Error> {
    if d.datatype()? == Type::Null {
        d.null()?;
        Ok(None)
    } else {
        Ok(Some(d.str()?.to_owned()))
    }
}

fn source_code(source: Source) -> u8 {
    match source {
        Source::Http => 0,
        Source::File => 1,
        Source::Cache => 3,
        Source::Embedded => 4,
        // Also any source added to ti-cache after this format: informational only, and
        // read back from here the body did come from a bundle.
        _ => 2,
    }
}

fn source_from_code(code: u8) -> Result<Source, minicbor::decode::Error> {
    Ok(match code {
        0 => Source::Http,
        1 => Source::File,
        2 => Source::Bundle,
        3 => Source::Cache,
        4 => Source::Embedded,
        _ => return Err(minicbor::decode::Error::message("unknown source code")),
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
    fn cbor_round_trip() {
        let original = bundle();
        assert_eq!(Bundle::from_slice(&original.to_vec()).unwrap(), original);
    }

    #[cfg(feature = "os")]
    #[test]
    fn file_round_trip() {
        let path = std::env::temp_dir().join(format!("ti-pki-bundle-{}.cbor", std::process::id()));
        let original = bundle();
        original.write(&path).unwrap();
        let read = Bundle::read(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read.unwrap(), original);
    }

    #[test]
    fn garbage_and_other_versions_are_rejected() {
        assert!(Bundle::from_slice(b"not cbor").is_err());
        let mut bytes = bundle().to_vec();
        bytes[1] = 2; // format_version, the first array element
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
