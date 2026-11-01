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

//! What is loaded: the two trust artefacts, the metadata that travels with their bytes,
//! and [`TrustMaterial`], the pair the reloader verifies and swaps as one.

use core::fmt;
use core::time::Duration;

use sha2::{Digest, Sha256};
use ti_store::{Meta, Source};

use crate::time::Timestamp;

/// One of the two artefacts a trust store is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Artifact {
    /// gematik's roots.json.
    Roots,
    /// The Trust Service Status List.
    Tsl,
    /// The detached signature of the list, the `.sig` file (`spec/tsl-detached`).
    TslSignature,
    /// The OCSP response for the list's signer, the `.ocsp` file.
    TslSignerStatus,
}

impl Artifact {
    /// Lowercase name: `roots` or `tsl`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Artifact::Roots => "roots",
            Artifact::Tsl => "tsl",
            Artifact::TslSignature => "tsl-sig",
            Artifact::TslSignerStatus => "tsl-ocsp",
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

/// The detached files loaded with a list (`spec/tsl-detached`): the signature, and the
/// signer's status when the source published one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detached {
    /// The `.sig` bytes.
    pub signature: Vec<u8>,
    /// Their metadata.
    pub signature_meta: Meta,
    /// The `.ocsp` bytes with their metadata, if loaded.
    pub signer_status: Option<(Vec<u8>, Meta)>,
}

/// The artefacts, loaded but not yet verified. They always travel together, so a trust
/// store never combines a new TSL with old roots, or a list with another list's
/// signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustMaterial {
    /// roots.json bytes.
    pub roots: Vec<u8>,
    /// TSL bytes.
    pub tsl: Vec<u8>,
    /// The older `fetched_at` of roots.json and the TSL; what freshness is measured from.
    pub fetched_at: Timestamp,
    /// Metadata of roots.json and the TSL, in that order.
    pub meta: [Meta; 2],
    /// The list's detached signature and signer status, when the source has them.
    /// Without them the list is verified by its enveloped signature.
    pub detached: Option<Detached>,
}

impl TrustMaterial {
    /// Pairs the two bodies with their metadata.
    pub fn new(roots: Vec<u8>, roots_meta: Meta, tsl: Vec<u8>, tsl_meta: Meta) -> Self {
        TrustMaterial {
            roots,
            tsl,
            fetched_at: roots_meta.fetched_at.min(tsl_meta.fetched_at),
            meta: [roots_meta, tsl_meta],
            detached: None,
        }
    }

    /// The same material with `detached` as its detached files. They do not change
    /// `fetched_at`: they are optional, and their age is bound by their own rules
    /// (TSLDET-013, 021), so a CRL host that is down costs no trust.
    #[must_use]
    pub fn with_detached(mut self, detached: Option<Detached>) -> Self {
        self.detached = detached;
        self
    }

    /// The body of `artifact`, if the material has it.
    pub fn body(&self, artifact: Artifact) -> Option<&[u8]> {
        match artifact {
            Artifact::Roots => Some(&self.roots),
            Artifact::Tsl => Some(&self.tsl),
            Artifact::TslSignature => self.detached.as_ref().map(|d| d.signature.as_slice()),
            Artifact::TslSignerStatus => self
                .detached
                .as_ref()
                .and_then(|d| d.signer_status.as_ref())
                .map(|(body, _)| body.as_slice()),
        }
    }

    /// The metadata of `artifact`, if the material has it.
    pub fn meta(&self, artifact: Artifact) -> Option<&Meta> {
        match artifact {
            Artifact::Roots => Some(&self.meta[0]),
            Artifact::Tsl => Some(&self.meta[1]),
            Artifact::TslSignature => self.detached.as_ref().map(|d| &d.signature_meta),
            Artifact::TslSignerStatus => self
                .detached
                .as_ref()
                .and_then(|d| d.signer_status.as_ref())
                .map(|(_, meta)| meta),
        }
    }

    /// The entity tags of every artefact, in the order of [`Artifact`]; `None` where
    /// the source gave none or the artefact is absent.
    pub fn etags(&self) -> Vec<Option<String>> {
        [
            Artifact::Roots,
            Artifact::Tsl,
            Artifact::TslSignature,
            Artifact::TslSignerStatus,
        ]
        .into_iter()
        .map(|artifact| self.meta(artifact).and_then(|m| m.etag.clone()))
        .collect()
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
