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

//! Section I: the byte formats of the files backend. The backend itself, which does the
//! I/O, belongs to the tools.

use ti_types::Timestamp;

use super::StoreError;
use super::backend::StoredRecord;
use super::names::{Field, MAX_TAGS, Name, Tag};
use super::record::MAX_TIME;
use super::wire::{Reader, put_lp};

/// STORE-080: a record file.
///
/// # Panics
///
/// Never for a record that passed [`StoredRecord::check`], which bounds the tags to 16.
pub fn encode_record(record: &StoredRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(14 + record.tags.len() * 70 + record.value.len());
    out.extend_from_slice(b"ZLRF");
    out.push(1);
    out.extend_from_slice(&record.expires_at.map_or(0, |t| t.0).to_be_bytes());
    out.push(u8::try_from(record.tags.len()).expect("at most 16 tags"));
    for t in &record.tags {
        put_lp(&mut out, t.field.as_str().as_bytes());
        out.extend_from_slice(&t.tag);
    }
    out.extend_from_slice(&record.value);
    out
}

/// STORE-080: parses a record file.
///
/// # Errors
///
/// `malformed`, `unsupported_version` or `limit_exceeded` as STORE-080 says.
pub fn parse_record(bytes: &[u8]) -> Result<StoredRecord, StoreError> {
    let mut r = Reader::new(bytes, "record file");
    if r.take(4)? != b"ZLRF" {
        return Err(r.malformed());
    }
    if r.u8()? != 1 {
        return Err(StoreError::UnsupportedVersion("record file"));
    }
    let expires_at = r.u64()?;
    if expires_at > MAX_TIME {
        return Err(StoreError::Malformed("record file"));
    }
    let count = usize::from(r.u8()?);
    if count > MAX_TAGS {
        return Err(StoreError::LimitExceeded("tags"));
    }
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        let field = core::str::from_utf8(r.lp()?)
            .ok()
            .and_then(|f| Field::new(f).ok())
            .ok_or(StoreError::Malformed("record file"))?;
        tags.push(Tag {
            field,
            tag: r.array()?,
        });
    }
    Ok(StoredRecord {
        value: r.rest().to_vec(),
        expires_at: (expires_at != 0).then_some(Timestamp(expires_at)),
        tags,
    })
}

/// STORE-080: the path of a record below `<root>/v1`, with `/` between the parts.
pub fn record_path(ns: &super::Namespace, name: &Name) -> String {
    use core::fmt::Write as _;
    let mut h = String::with_capacity(64);
    for b in name.0 {
        let _ = write!(h, "{b:02x}");
    }
    format!("{ns}/{}/{}/{h}.rec", &h[..2], &h[2..4])
}

/// STORE-086: the format level of a files tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesMeta {
    /// The level the tree is at.
    pub level: u16,
    /// The lowest level a reader must support.
    pub min_compatible: u16,
}

impl FilesMeta {
    /// Parses `<root>/meta`.
    ///
    /// # Errors
    ///
    /// `malformed` for another magic, trailing bytes or levels out of order.
    pub fn parse(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader::new(bytes, "files meta");
        if r.take(4)? != b"ZLFM" {
            return Err(r.malformed());
        }
        let meta = FilesMeta {
            level: r.u16()?,
            min_compatible: r.u16()?,
        };
        if !r.is_empty() || meta.min_compatible < 1 || meta.min_compatible > meta.level {
            return Err(StoreError::Malformed("files meta"));
        }
        Ok(meta)
    }

    /// The bytes of `<root>/meta`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"ZLFM".to_vec();
        out.extend_from_slice(&self.level.to_be_bytes());
        out.extend_from_slice(&self.min_compatible.to_be_bytes());
        out
    }
}
