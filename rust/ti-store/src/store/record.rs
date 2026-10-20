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

//! Sections E and F: key derivation, sealed records (version 1) and plain records
//! (version 0).

use aes_gcm::AesGcm;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag as GcmTag};
use aes_gcm::aes::Aes256;
use hkdf::Hkdf;
use sha2::Sha256;
use ti_types::Timestamp;
use zeroize::Zeroizing;

use super::StoreError;
use super::names::{Field, Kid, Name, Namespace, Tag, sealed_name, sealed_tag};
use super::wire::{Reader, put_lp};

type Aes256Gcm = AesGcm<Aes256, U12>;

const LABEL: &str = "zl-store/1";
/// STORE-002: the latest time a record, record file or keyring holds,
/// 9999-12-31T23:59:59Z, so that every language's time type holds it.
pub const MAX_TIME: u64 = 253_402_300_799;

/// STORE-002: a writer refuses a time beyond [`MAX_TIME`].
pub(crate) fn check_write_time(t: Option<Timestamp>) -> Result<(), StoreError> {
    if t.is_some_and(|t| t.0 > MAX_TIME) {
        return Err(StoreError::InvalidArgument("time beyond 9999"));
    }
    Ok(())
}

/// STORE-054: the largest payload of a record.
pub const MAX_PAYLOAD: usize = 16 << 20;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// A data key (STORE-040): 32 bytes, overwritten when dropped.
pub struct DataKey(pub(crate) Zeroizing<[u8; 32]>);

impl DataKey {
    /// Takes the bytes of a data key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        DataKey(Zeroizing::new(bytes))
    }

    /// The key bytes, for wrapping. Only wrappers and the keyring need them.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DataKey(…)")
    }
}

/// The three keys of STORE-041.
pub struct DerivedKeys {
    pub(crate) value: Zeroizing<[u8; 32]>,
    pub(crate) name: Zeroizing<[u8; 32]>,
    pub(crate) index: Zeroizing<[u8; 32]>,
}

impl DerivedKeys {
    /// `k_value`, `k_name` and `k_index`, for test vectors.
    pub fn expose(&self) -> (&[u8; 32], &[u8; 32], &[u8; 32]) {
        (&self.value, &self.name, &self.index)
    }

    /// STORE-031: the name of `id` under these keys as the index kid's.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for an id longer than 4096 bytes.
    pub fn name(&self, ns: &Namespace, id: &[u8]) -> Result<Name, StoreError> {
        sealed_name(&self.name, ns, id)
    }

    /// STORE-034: a tag under these keys as the index kid's.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` for a value longer than 4096 bytes.
    pub fn tag(&self, ns: &Namespace, field: &Field, value: &[u8]) -> Result<Tag, StoreError> {
        sealed_tag(&self.index, ns, field, value)
    }

    /// `k_value`, for [`seal_record`] and [`open_sealed`].
    pub fn value_key(&self) -> &[u8; 32] {
        &self.value
    }
}

/// STORE-041: `HKDF-SHA-256(dk, salt = "zl-store/1", info)` for the value, name and index
/// keys.
///
/// # Panics
///
/// Never: the output length is fixed and valid for HKDF-SHA-256.
pub fn derive(dk: &DataKey) -> DerivedKeys {
    let hk = Hkdf::<Sha256>::new(Some(LABEL.as_bytes()), dk.0.as_slice());
    let expand = |info: &str| {
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info.as_bytes(), out.as_mut_slice())
            .expect("32 bytes is a valid HKDF-SHA-256 length");
        out
    };
    DerivedKeys {
        value: expand("value"),
        name: expand("name"),
        index: expand("index"),
    }
}

fn wire_time(t: Option<Timestamp>) -> u64 {
    t.map_or(0, |t| t.0)
}

/// STORE-055: the associated data that binds a record to its profile, kid, namespace,
/// name and expiry.
fn aad(profile_id: &[u8; 16], kid: &[u8], ns: &Namespace, name: &Name, not_after: u64) -> Vec<u8> {
    let mut a = Vec::with_capacity(96 + kid.len() + ns.as_str().len());
    put_lp(&mut a, LABEL.as_bytes());
    put_lp(&mut a, profile_id);
    put_lp(&mut a, kid);
    put_lp(&mut a, ns.as_str().as_bytes());
    put_lp(&mut a, &name.0);
    a.extend_from_slice(&not_after.to_be_bytes());
    a
}

/// Section F: a sealed record of `payload` under `k_value`. The nonce MUST be fresh
/// random bytes (STORE-052); [`Keyring`](super::Keyring) draws it.
///
/// # Errors
///
/// `limit_exceeded` for a payload above 16 MiB.
///
/// # Panics
///
/// Never: a [`Kid`] has at most 64 bytes.
#[allow(
    clippy::too_many_arguments,
    reason = "every argument is a field of the record or its AAD"
)]
pub fn seal_record(
    k_value: &[u8; 32],
    profile_id: &[u8; 16],
    kid: &Kid,
    ns: &Namespace,
    name: &Name,
    not_after: Option<Timestamp>,
    nonce: &[u8; NONCE_LEN],
    payload: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(StoreError::LimitExceeded("payload"));
    }
    check_write_time(not_after)?;
    let na = wire_time(not_after);
    let kid_b = kid.as_str().as_bytes();
    let cipher = Aes256Gcm::new_from_slice(k_value).expect("32-byte key");
    let mut out = Vec::with_capacity(2 + kid_b.len() + 8 + NONCE_LEN + payload.len() + TAG_LEN);
    out.push(1);
    out.push(u8::try_from(kid_b.len()).expect("a kid has at most 64 bytes"));
    out.extend_from_slice(kid_b);
    out.extend_from_slice(&na.to_be_bytes());
    out.extend_from_slice(nonce);
    let start = out.len();
    out.extend_from_slice(payload);
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::<Aes256Gcm>::from(*nonce),
            &aad(profile_id, kid_b, ns, name, na),
            out[start..].as_mut().into(),
        )
        .map_err(|_| StoreError::LimitExceeded("payload"))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

/// An opened record.
#[derive(Debug)]
pub struct Opened {
    /// The kid it was sealed under; none for a plain record.
    pub kid: Option<Kid>,
    /// Its expiry.
    pub not_after: Option<Timestamp>,
    /// Its payload, overwritten when dropped.
    pub payload: Zeroizing<Vec<u8>>,
}

fn check_expiry(not_after: u64, now: Timestamp) -> Result<Option<Timestamp>, StoreError> {
    // STORE-003: live while not_after is 0 or later than now.
    if not_after != 0 && not_after <= now.0 {
        return Err(StoreError::Expired);
    }
    Ok((not_after != 0).then_some(Timestamp(not_after)))
}

/// STORE-050, STORE-051, STORE-054 to STORE-056: opens a sealed record. `k_value` looks up
/// the value key of a kid. The tag is checked before any plaintext leaves, and the expiry
/// only after the tag, so that the code reports what the record really is.
///
/// # Errors
///
/// `malformed`, `unsupported_version`, `limit_exceeded`, `unknown_kid`,
/// `auth_failed` or `expired`, in the order of STORE-055.
///
/// # Panics
///
/// Never: the key is 32 bytes.
pub fn open_sealed<'k>(
    k_value: impl Fn(&Kid) -> Option<&'k [u8; 32]>,
    profile_id: &[u8; 16],
    ns: &Namespace,
    name: &Name,
    now: Timestamp,
    record: &[u8],
) -> Result<Opened, StoreError> {
    let mut r = Reader::new(record, "record");
    if r.u8()? != 1 {
        return Err(StoreError::UnsupportedVersion("record"));
    }
    let kid_len = usize::from(r.u8()?);
    if !(1..=64).contains(&kid_len) {
        return Err(r.malformed());
    }
    let kid_b = r.take(kid_len)?;
    let kid = Kid::from_bytes(kid_b).ok_or(StoreError::Malformed("record"))?;
    let na = r.u64()?;
    if na > MAX_TIME {
        return Err(StoreError::Malformed("record"));
    }
    let nonce: [u8; NONCE_LEN] = r.array()?;
    let body = r.rest();
    if body.len() < TAG_LEN {
        return Err(StoreError::Malformed("record"));
    }
    if body.len() - TAG_LEN > MAX_PAYLOAD {
        return Err(StoreError::LimitExceeded("payload"));
    }
    let key = k_value(&kid).ok_or(StoreError::UnknownKid)?;
    let (ct, tag) = body.split_at(body.len() - TAG_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let tag = GcmTag::<Aes256Gcm>::try_from(tag).map_err(|_| StoreError::Malformed("record"))?;
    let mut buf = Zeroizing::new(ct.to_vec());
    cipher
        .decrypt_inout_detached(
            &Nonce::<Aes256Gcm>::from(nonce),
            &aad(profile_id, kid_b, ns, name, na),
            buf.as_mut_slice().into(),
            &tag,
        )
        .map_err(|_| StoreError::AuthFailed("record"))?;
    let not_after = check_expiry(na, now)?;
    Ok(Opened {
        kid: Some(kid),
        not_after,
        payload: buf,
    })
}

/// What a record's header says without opening it: the kid of a sealed record, the
/// expiry and the payload's size (STORE-044, STORE-124). None of it is authenticated
/// until the record is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordHeader {
    /// The kid of a sealed record; none for a plain one.
    pub kid: Option<Kid>,
    /// The expiry; none for a record that does not expire.
    pub not_after: Option<Timestamp>,
    /// The size of the payload.
    pub payload_len: usize,
}

/// STORE-050, STORE-051, STORE-057: reads a record's header with the checks opening it
/// would make before any key is needed.
///
/// # Errors
///
/// `malformed`, `unsupported_version` or `limit_exceeded`.
pub fn record_header(record: &[u8]) -> Result<RecordHeader, StoreError> {
    let mut r = Reader::new(record, "record");
    let version = r.u8()?;
    let kid = match version {
        0 => None,
        1 => {
            let kid_len = usize::from(r.u8()?);
            if !(1..=64).contains(&kid_len) {
                return Err(r.malformed());
            }
            Some(Kid::from_bytes(r.take(kid_len)?).ok_or(StoreError::Malformed("record"))?)
        }
        _ => return Err(StoreError::UnsupportedVersion("record")),
    };
    let na = r.u64()?;
    if na > MAX_TIME {
        return Err(StoreError::Malformed("record"));
    }
    let payload_len = if kid.is_some() {
        let _: [u8; NONCE_LEN] = r.array()?;
        r.rest()
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(StoreError::Malformed("record"))?
    } else {
        r.rest().len()
    };
    if payload_len > MAX_PAYLOAD {
        return Err(StoreError::LimitExceeded("payload"));
    }
    Ok(RecordHeader {
        kid,
        not_after: (na != 0).then_some(Timestamp(na)),
        payload_len,
    })
}

/// Section F: a plain record.
///
/// # Errors
///
/// `limit_exceeded` for a payload above 16 MiB.
pub fn plain_record(not_after: Option<Timestamp>, payload: &[u8]) -> Result<Vec<u8>, StoreError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(StoreError::LimitExceeded("payload"));
    }
    check_write_time(not_after)?;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push(0);
    out.extend_from_slice(&wire_time(not_after).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// STORE-050, STORE-054, STORE-057: opens a plain record. It has no integrity of its own.
///
/// # Errors
///
/// `malformed`, `unsupported_version`, `limit_exceeded` or `expired`.
pub fn open_plain(now: Timestamp, record: &[u8]) -> Result<Opened, StoreError> {
    let mut r = Reader::new(record, "record");
    if r.u8()? != 0 {
        return Err(StoreError::UnsupportedVersion("record"));
    }
    let na = r.u64()?;
    if na > MAX_TIME {
        return Err(StoreError::Malformed("record"));
    }
    let payload = r.rest();
    if payload.len() > MAX_PAYLOAD {
        return Err(StoreError::LimitExceeded("payload"));
    }
    let not_after = check_expiry(na, now)?;
    Ok(Opened {
        kid: None,
        not_after,
        payload: Zeroizing::new(payload.to_vec()),
    })
}
