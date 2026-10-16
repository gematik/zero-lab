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

//! Section C and D: namespaces, field names, kids, and the hashed names and tags that the
//! backend sees in place of ids and metadata.

use core::fmt;

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::StoreError;
use super::wire::put_lp;

/// STORE-030, STORE-033: the longest id and tag value.
pub const MAX_ID: usize = 4096;
/// STORE-033: the most tags a record carries.
pub const MAX_TAGS: usize = 16;

/// A namespace: `[a-z0-9][a-z0-9.-]{0,63}` (STORE-020).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Namespace(String);

impl Namespace {
    /// A namespace, if `s` has the syntax of STORE-020. Whether it is registered is the
    /// [`Store`](super::Store)'s concern.
    ///
    /// # Errors
    ///
    /// `invalid_argument` outside the syntax.
    pub fn new(s: &str) -> Result<Self, StoreError> {
        let b = s.as_bytes();
        let first = b
            .first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest = b
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-');
        if first && rest && b.len() <= 64 {
            Ok(Namespace(s.to_owned()))
        } else {
            Err(StoreError::InvalidArgument("namespace"))
        }
    }

    /// The namespace as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An indexed field name: `[a-z0-9_]{1,32}` (STORE-033).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Field(String);

impl Field {
    /// A field name, if `s` has the syntax of STORE-033.
    ///
    /// # Errors
    ///
    /// `invalid_argument` outside the syntax.
    pub fn new(s: &str) -> Result<Self, StoreError> {
        let ok = (1..=32).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
        if ok {
            Ok(Field(s.to_owned()))
        } else {
            Err(StoreError::InvalidArgument("field"))
        }
    }

    /// The field name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A key id: 1 to 64 bytes of printable ASCII without space (STORE-051).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(String);

impl Kid {
    /// A kid, if `s` has the syntax of STORE-051.
    ///
    /// # Errors
    ///
    /// `invalid_argument` outside the syntax.
    pub fn new(s: &str) -> Result<Self, StoreError> {
        Self::from_bytes(s.as_bytes()).ok_or(StoreError::InvalidArgument("kid"))
    }

    pub(crate) fn from_bytes(b: &[u8]) -> Option<Self> {
        let ok = (1..=64).contains(&b.len()) && b.iter().all(|c| (b'!'..=b'~').contains(c));
        // ASCII checked above, so the bytes are UTF-8.
        ok.then(|| Kid(String::from_utf8_lossy(b).into_owned()))
    }

    /// The kid as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The 32 bytes a backend stores in place of an id (STORE-030).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(pub [u8; 32]);

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A name is a keyed hash and safe to show; eight bytes identify it in a trace.
        write!(f, "Name(")?;
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…)")
    }
}

impl TryFrom<&[u8]> for Name {
    type Error = StoreError;

    fn try_from(b: &[u8]) -> Result<Self, StoreError> {
        b.try_into()
            .map(Name)
            .map_err(|_| StoreError::InvalidArgument("name"))
    }
}

/// A blind-index tag: the field name in clear and the hash of its value (STORE-034).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag {
    /// The field, stored as is.
    pub field: Field,
    /// The hash of the value.
    pub tag: [u8; 32],
}

fn check_id(id: &[u8]) -> Result<(), StoreError> {
    if id.len() > MAX_ID {
        Err(StoreError::LimitExceeded("id"))
    } else {
        Ok(())
    }
}

fn check_value(value: &[u8]) -> Result<(), StoreError> {
    if value.len() > MAX_ID {
        Err(StoreError::LimitExceeded("tag value"))
    } else {
        Ok(())
    }
}

fn name_input(ns: &Namespace, id: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + ns.0.len() + id.len());
    put_lp(&mut m, ns.0.as_bytes());
    put_lp(&mut m, id);
    m
}

fn tag_input(ns: &Namespace, field: &Field, value: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(12 + ns.0.len() + field.0.len() + value.len());
    put_lp(&mut m, ns.0.as_bytes());
    put_lp(&mut m, field.0.as_bytes());
    put_lp(&mut m, value);
    m
}

fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut mac =
        <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn sha256_labelled(label: &str, msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut l = Vec::new();
    put_lp(&mut l, label.as_bytes());
    h.update(&l);
    h.update(msg);
    h.finalize().into()
}

/// STORE-031: the name of `id` in a sealed namespace.
pub(crate) fn sealed_name(
    k_name: &[u8; 32],
    ns: &Namespace,
    id: &[u8],
) -> Result<Name, StoreError> {
    check_id(id)?;
    Ok(Name(hmac_sha256(k_name, &name_input(ns, id))))
}

/// STORE-034: a tag in a sealed namespace.
pub(crate) fn sealed_tag(
    k_index: &[u8; 32],
    ns: &Namespace,
    field: &Field,
    value: &[u8],
) -> Result<Tag, StoreError> {
    check_value(value)?;
    Ok(Tag {
        field: field.clone(),
        tag: hmac_sha256(k_index, &tag_input(ns, field, value)),
    })
}

/// STORE-032: the name of `id` in a plain namespace.
///
/// # Errors
///
/// `limit_exceeded` for an id longer than 4096 bytes.
pub fn plain_name(ns: &Namespace, id: &[u8]) -> Result<Name, StoreError> {
    check_id(id)?;
    Ok(Name(sha256_labelled(
        "zl-store/1/plain-name",
        &name_input(ns, id),
    )))
}

/// STORE-034: a tag in a plain namespace.
///
/// # Errors
///
/// `limit_exceeded` for a value longer than 4096 bytes.
pub fn plain_tag(ns: &Namespace, field: &Field, value: &[u8]) -> Result<Tag, StoreError> {
    check_value(value)?;
    Ok(Tag {
        field: field.clone(),
        tag: sha256_labelled("zl-store/1/plain-tag", &tag_input(ns, field, value)),
    })
}
