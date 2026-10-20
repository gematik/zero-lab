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

//! The download cache of ti-pki and ti-connector-client in the profile's `cache.db`: a
//! [`CacheStore`] over the store's plain cache namespaces.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use ti_store::store::StoreError;
use ti_store::store::registry::{CONNECTOR_SDS, NamespaceSpec, PKI_OCSP, PKI_ROOTS, PKI_TSL};
use ti_store::{CacheEntry, CacheError, CacheStore, Meta, Source};
use ti_types::Timestamp;

use super::profile::{ProfileStore, now};

/// The cache keys the libraries use, and the namespace each belongs to; the rest of the
/// key is the record's id.
const PREFIXES: [(&str, &NamespaceSpec); 4] = [
    ("ti-pki/v1/tsl/", &PKI_TSL),
    ("ti-pki/v1/roots/", &PKI_ROOTS),
    ("ti-pki/v1/ocsp/", &PKI_OCSP),
    ("ti-connector/v1/sds/", &CONNECTOR_SDS),
];

/// The payload's version (STORE-110).
const PAYLOAD_V1: u8 = 1;

/// Cache entries as records of the profile's cache.
#[derive(Debug)]
pub struct StoreCache(pub ProfileStore);

#[derive(Serialize, Deserialize)]
struct StoredMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    fetched_at: u64,
    max_age_secs: Option<u64>,
}

fn locate(key: &str) -> Result<(&'static NamespaceSpec, &str), CacheError> {
    PREFIXES
        .iter()
        .find_map(|(prefix, spec)| key.strip_prefix(prefix).map(|id| (*spec, id)))
        .filter(|(_, id)| !id.is_empty())
        .ok_or_else(|| error(format!("no cache namespace for key {key:?}")))
}

/// `u8 1 ‖ u32 length ‖ metadata as JSON ‖ body`.
fn encode(entry: &CacheEntry) -> Result<Vec<u8>, CacheError> {
    let meta = serde_json::to_vec(&StoredMeta {
        etag: entry.meta.etag.clone(),
        last_modified: entry.meta.last_modified.clone(),
        fetched_at: entry.meta.fetched_at.0,
        max_age_secs: entry.meta.max_age.map(|age| age.as_secs()),
    })
    .map_err(|e| error(e.to_string()))?;
    let len = u32::try_from(meta.len()).map_err(|_| error("cache metadata too large".into()))?;
    let mut out = Vec::with_capacity(5 + meta.len() + entry.body.len());
    out.push(PAYLOAD_V1);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&entry.body);
    Ok(out)
}

/// The entry, or none for a payload this version does not read: a cache entry that
/// cannot be read is a miss.
fn decode(payload: &[u8]) -> Option<CacheEntry> {
    let (&version, rest) = payload.split_first()?;
    if version != PAYLOAD_V1 || rest.len() < 4 {
        return None;
    }
    let (len, rest) = rest.split_at(4);
    let len = usize::try_from(u32::from_be_bytes(len.try_into().ok()?)).ok()?;
    if rest.len() < len {
        return None;
    }
    let (meta, body) = rest.split_at(len);
    let meta: StoredMeta = serde_json::from_slice(meta).ok()?;
    Some(CacheEntry {
        body: body.to_vec(),
        meta: Meta {
            etag: meta.etag,
            last_modified: meta.last_modified,
            fetched_at: Timestamp(meta.fetched_at),
            max_age: meta.max_age_secs.map(Duration::from_secs),
            source: Source::Cache,
        },
    })
}

impl CacheStore for StoreCache {
    async fn get(&self, key: &str) -> Result<Option<CacheEntry>, CacheError> {
        let (spec, id) = locate(key)?;
        match self.0.get(spec, id.as_bytes(), now()).await {
            Ok(stored) => Ok(decode(&stored.payload)),
            Err(StoreError::NotFound) => Ok(None),
            Err(e) => Err(error(format!("cache {}: {e}", spec.name))),
        }
    }

    /// Kept for the namespace's lifetime; whether an entry is fresh is the cache
    /// policy's question, answered from its metadata.
    async fn put(&self, key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        let (spec, id) = locate(key)?;
        let now = now();
        let expires_at = Timestamp(now.0 + spec.max_ttl);
        self.0
            .put(
                spec,
                id.as_bytes(),
                &encode(entry)?,
                &[],
                Some(expires_at),
                now,
            )
            .await
            .map(drop)
            .map_err(|e| error(format!("cache {}: {e}", spec.name)))
    }
}

fn error(message: String) -> CacheError {
    CacheError { message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_library_key_has_a_namespace() {
        for key in [
            "ti-pki/v1/tsl/0123456789abcdef",
            "ti-pki/v1/roots/0123456789abcdef",
            "ti-pki/v1/ocsp/ab/cd",
            "ti-connector/v1/sds/0123456789abcdef",
        ] {
            assert!(locate(key).is_ok(), "{key}");
        }
        assert!(locate("ti-pki/v1/tsl/").is_err());
        assert!(locate("other/key").is_err());
    }

    #[test]
    fn payload_round_trips_and_unknown_versions_are_misses() {
        let entry = CacheEntry {
            body: b"<tsl/>".to_vec(),
            meta: Meta {
                etag: Some("\"e\"".into()),
                last_modified: None,
                fetched_at: Timestamp(1_700_000_000),
                max_age: Some(Duration::from_secs(60)),
                source: Source::Http,
            },
        };
        let payload = encode(&entry).expect("encode");
        let back = decode(&payload).expect("decode");
        assert_eq!(back.body, entry.body);
        assert_eq!(back.meta.etag, entry.meta.etag);
        assert_eq!(back.meta.fetched_at, entry.meta.fetched_at);
        assert_eq!(back.meta.max_age, entry.meta.max_age);
        assert_eq!(back.meta.source, Source::Cache);
        let mut other = payload.clone();
        other[0] = 2;
        assert!(decode(&other).is_none());
        assert!(decode(&payload[..3]).is_none());
    }
}
