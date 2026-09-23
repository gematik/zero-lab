//! What is loaded: the two trust artefacts, the metadata that travels with their bytes,
//! and [`TrustMaterial`], the pair the reloader verifies and swaps as one.

use core::fmt;
use core::time::Duration;

use sha2::{Digest, Sha256};

use super::clock::Timestamp;

/// One of the two artefacts a trust store is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Artifact {
    /// gematik's roots.json.
    Roots,
    /// The Trust Service Status List.
    Tsl,
}

impl Artifact {
    /// Lowercase name: `roots` or `tsl`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Artifact::Roots => "roots",
            Artifact::Tsl => "tsl",
        }
    }

    /// Cache key `ti-pki/v1/{roots|tsl}/<id>`, where `<id>` is the first 16 hex digits
    /// of the SHA-256 of `source` (the download URL). Keys follow the source, not the
    /// environment, so two configurations share cache entries exactly when they load
    /// from the same place.
    pub fn cache_key(self, source: &str) -> String {
        let digest = Sha256::digest(source.as_bytes());
        format!("ti-pki/v1/{}/{}", self.as_str(), &hex(&digest)[..16])
    }
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a body came from. Informational only: trust never depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// Fetched over HTTP.
    Http,
    /// Read from a file.
    File,
    /// Taken from an offline bundle.
    Bundle,
    /// Served by a cache store.
    Cache,
    /// Compiled into the binary.
    Embedded,
}

/// Metadata of a loaded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// HTTP `ETag`, or `sha256:<hex>` of the body for file and bundle sources.
    pub etag: Option<String>,
    /// HTTP `Last-Modified`, verbatim.
    pub last_modified: Option<String>,
    /// When the body was obtained from its origin; revalidation moves it forward.
    pub fetched_at: Timestamp,
    /// `Cache-Control: max-age` of the response, if any.
    pub max_age: Option<Duration>,
    /// Where the body came from.
    pub source: Source,
}

/// What a transport reports alongside a response; [`Meta`] without the time, which the
/// loader stamps with its clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseMeta {
    /// See [`Meta::etag`].
    pub etag: Option<String>,
    /// See [`Meta::last_modified`].
    pub last_modified: Option<String>,
    /// See [`Meta::max_age`].
    pub max_age: Option<Duration>,
    /// See [`Meta::source`].
    pub source: Source,
}

impl ResponseMeta {
    /// Completes the metadata with the time the response was obtained.
    pub fn at(self, fetched_at: Timestamp) -> Meta {
        Meta {
            etag: self.etag,
            last_modified: self.last_modified,
            fetched_at,
            max_age: self.max_age,
            source: self.source,
        }
    }
}

/// A request for one artefact. The URL comes from the
/// [`TrustConfig`](crate::TrustConfig); loaders never invent URLs.
#[derive(Clone, Copy, Debug)]
pub struct ArtifactRequest<'a> {
    /// Which artefact.
    pub artifact: Artifact,
    /// Where to get it.
    pub url: &'a str,
    /// Validator for `If-None-Match`.
    pub etag: Option<&'a str>,
    /// Validator for `If-Modified-Since`.
    pub last_modified: Option<&'a str>,
}

/// A transport's answer.
#[derive(Clone, Debug)]
pub enum ArtifactResponse {
    /// A new body.
    Fresh {
        /// The bytes.
        body: Vec<u8>,
        /// Their metadata.
        meta: ResponseMeta,
    },
    /// The validators matched; the caller's copy is current.
    NotModified {
        /// Metadata of the confirmation.
        meta: ResponseMeta,
    },
}

/// Both artefacts, loaded but not yet verified. They always travel together, so a
/// trust store never combines a new TSL with old roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustMaterial {
    /// roots.json bytes.
    pub roots: Vec<u8>,
    /// TSL bytes.
    pub tsl: Vec<u8>,
    /// The older of the two `fetched_at`; what freshness is measured from.
    pub fetched_at: Timestamp,
    /// Metadata of roots.json and the TSL, in that order.
    pub meta: [Meta; 2],
}

impl TrustMaterial {
    /// Pairs the two bodies with their metadata.
    pub fn new(roots: Vec<u8>, roots_meta: Meta, tsl: Vec<u8>, tsl_meta: Meta) -> Self {
        TrustMaterial {
            roots,
            tsl,
            fetched_at: roots_meta.fetched_at.min(tsl_meta.fetched_at),
            meta: [roots_meta, tsl_meta],
        }
    }

    /// The body of `artifact`.
    pub fn body(&self, artifact: Artifact) -> &[u8] {
        match artifact {
            Artifact::Roots => &self.roots,
            Artifact::Tsl => &self.tsl,
        }
    }

    /// The metadata of `artifact`.
    pub fn meta(&self, artifact: Artifact) -> &Meta {
        match artifact {
            Artifact::Roots => &self.meta[0],
            Artifact::Tsl => &self.meta[1],
        }
    }
}

/// `sha256:<hex>` of `body`, the entity tag for sources without HTTP validators.
pub fn content_etag(body: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(body)))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            write!(s, "{b:02x}").expect("writing to a String cannot fail");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_follows_the_source() {
        let prod = Artifact::Tsl.cache_key(crate::tsl::URL_PROD);
        assert!(prod.starts_with("ti-pki/v1/tsl/"));
        assert_eq!(prod.len(), "ti-pki/v1/tsl/".len() + 16);
        assert_eq!(prod, Artifact::Tsl.cache_key(crate::tsl::URL_PROD));
        assert_ne!(prod, Artifact::Tsl.cache_key(crate::tsl::URL_TEST));
        assert_ne!(prod, Artifact::Roots.cache_key(crate::tsl::URL_PROD));
    }

    #[test]
    fn content_etag_is_sha256() {
        assert_eq!(
            content_etag(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
