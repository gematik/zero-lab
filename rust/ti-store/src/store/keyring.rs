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

//! Section G: the keyring file, the wrappers that protect its data keys, and the unwrapped
//! keyring that seals records.

use core::fmt::Write as _;
use std::collections::BTreeMap;

use aes_gcm::AesGcm;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag as GcmTag};
use aes_gcm::aes::Aes256;
use ti_types::Timestamp;
use zeroize::Zeroizing;

use super::StoreError;
use super::names::{Field, Kid, Name, Namespace, Tag};
use super::random::Random;
use super::record::{DataKey, DerivedKeys, MAX_TIME, Opened, derive, open_sealed, seal_record};
use super::sealer::Sealer;
use super::wire::{Reader, put_lp};

type Aes256Gcm = AesGcm<Aes256, U12>;

/// One entry of a keyring file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// The kid.
    pub kid: Kid,
    /// When the key was created.
    pub created: Timestamp,
    /// The wrapper that protects it (wrapper registry).
    pub wrapper_id: String,
    /// The data key as the wrapper protects it.
    pub wrapped: Vec<u8>,
}

/// A keyring file as stored (STORE-060 to STORE-063). It holds no key in clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyringFile {
    /// The profile id.
    pub profile_id: [u8; 16],
    /// The kid that seals new records.
    pub current_kid: Kid,
    /// The kid whose keys make names and tags.
    pub index_kid: Kid,
    /// The wrapped data keys.
    pub entries: Vec<WrappedKey>,
}

const MAGIC: &[u8; 4] = b"ZLKR";

fn wrapper_id_valid(b: &[u8]) -> bool {
    (1..=32).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

impl KeyringFile {
    /// Parses a keyring file (STORE-005, STORE-060, STORE-062).
    ///
    /// # Errors
    ///
    /// `malformed` for a structural error, `unsupported_version` for another version.
    pub fn parse(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut r = Reader::new(bytes, "keyring");
        if r.take(4)? != MAGIC {
            return Err(r.malformed());
        }
        if r.u8()? != 1 {
            return Err(StoreError::UnsupportedVersion("keyring"));
        }
        let profile_id = r.array()?;
        let current_kid = Kid::from_bytes(r.lp()?).ok_or(StoreError::Malformed("keyring"))?;
        let index_kid = Kid::from_bytes(r.lp()?).ok_or(StoreError::Malformed("keyring"))?;
        let count = r.u16()?;
        if !(1..=256).contains(&count) {
            return Err(r.malformed());
        }
        let mut entries: Vec<WrappedKey> = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let kid = Kid::from_bytes(r.lp()?).ok_or(StoreError::Malformed("keyring"))?;
            let created = Timestamp(r.u64()?);
            let id = r.lp()?;
            let wrapped = r.lp()?.to_vec();
            if !wrapper_id_valid(id) || entries.iter().any(|e| e.kid == kid) || created.0 > MAX_TIME
            {
                return Err(StoreError::Malformed("keyring"));
            }
            let wrapper_id = String::from_utf8_lossy(id).into_owned();
            entries.push(WrappedKey {
                kid,
                created,
                wrapper_id,
                wrapped,
            });
        }
        if !r.is_empty() {
            return Err(StoreError::Malformed("keyring"));
        }
        let file = KeyringFile {
            profile_id,
            current_kid,
            index_kid,
            entries,
        };
        if file.entry(&file.current_kid).is_none() || file.entry(&file.index_kid).is_none() {
            return Err(StoreError::Malformed("keyring"));
        }
        Ok(file)
    }

    /// The file's bytes (section G).
    ///
    /// # Panics
    ///
    /// Never for a file built from a parsed or created keyring, which has at most 256 entries.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.extend_from_slice(&self.profile_id);
        put_lp(&mut out, self.current_kid.as_str().as_bytes());
        put_lp(&mut out, self.index_kid.as_str().as_bytes());
        out.extend_from_slice(
            &u16::try_from(self.entries.len())
                .expect("at most 256 entries")
                .to_be_bytes(),
        );
        for e in &self.entries {
            put_lp(&mut out, e.kid.as_str().as_bytes());
            out.extend_from_slice(&e.created.0.to_be_bytes());
            put_lp(&mut out, e.wrapper_id.as_bytes());
            put_lp(&mut out, &e.wrapped);
        }
        out
    }

    fn entry(&self, kid: &Kid) -> Option<&WrappedKey> {
        self.entries.iter().find(|e| &e.kid == kid)
    }
}

/// Protects data keys in a keyring file (wrapper registry). Asynchronous, because a
/// platform wrapper may wait for a device or a user.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait KeyWrapper {
    /// The wrapper id of the registry.
    fn id(&self) -> &str;
    /// Wraps `dk`, bound to the profile and kid (STORE-063).
    async fn wrap(
        &self,
        profile_id: &[u8; 16],
        kid: &Kid,
        dk: &DataKey,
    ) -> Result<Vec<u8>, StoreError>;
    /// Unwraps a data key; `auth_failed` if it was altered or bound elsewhere (STORE-064).
    async fn unwrap(
        &self,
        profile_id: &[u8; 16],
        kid: &Kid,
        wrapped: &[u8],
    ) -> Result<DataKey, StoreError>;
}

/// The `key-file` wrapper: AES-256-GCM under a key-encryption key read from a file
/// (STORE-094).
pub struct KeyFileWrapper<R> {
    kek: Zeroizing<[u8; 32]>,
    random: R,
}

impl<R: Random> KeyFileWrapper<R> {
    /// A wrapper with the key from [`parse_kek_file`](super::parse_kek_file).
    pub fn new(kek: Zeroizing<[u8; 32]>, random: R) -> Self {
        KeyFileWrapper { kek, random }
    }

    fn aad(profile_id: &[u8; 16], kid: &Kid) -> Vec<u8> {
        let mut a = Vec::new();
        put_lp(&mut a, b"zl-keyring/1");
        put_lp(&mut a, profile_id);
        put_lp(&mut a, kid.as_str().as_bytes());
        a
    }
}

impl<R> core::fmt::Debug for KeyFileWrapper<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyFileWrapper(…)")
    }
}

impl<R: Random> KeyWrapper for KeyFileWrapper<R> {
    fn id(&self) -> &'static str {
        "key-file"
    }

    async fn wrap(
        &self,
        profile_id: &[u8; 16],
        kid: &Kid,
        dk: &DataKey,
    ) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0u8; 12];
        self.random.fill(&mut nonce)?;
        let cipher = Aes256Gcm::new_from_slice(self.kek.as_slice()).expect("32-byte key");
        let mut out = Vec::with_capacity(60);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(dk.expose());
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::<Aes256Gcm>::from(nonce),
                &Self::aad(profile_id, kid),
                out[12..].as_mut().into(),
            )
            .map_err(|_| StoreError::Backend("key wrap".into()))?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    async fn unwrap(
        &self,
        profile_id: &[u8; 16],
        kid: &Kid,
        wrapped: &[u8],
    ) -> Result<DataKey, StoreError> {
        if wrapped.len() != 60 {
            return Err(StoreError::Malformed("wrapped key"));
        }
        let (nonce, rest) = wrapped.split_at(12);
        let (ct, tag) = rest.split_at(32);
        let cipher = Aes256Gcm::new_from_slice(self.kek.as_slice()).expect("32-byte key");
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce).expect("12 bytes");
        let tag = GcmTag::<Aes256Gcm>::try_from(tag).expect("16 bytes");
        let mut dk = Zeroizing::new([0u8; 32]);
        dk.copy_from_slice(ct);
        cipher
            .decrypt_inout_detached(
                &nonce,
                &Self::aad(profile_id, kid),
                dk.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_| StoreError::AuthFailed("wrapped key"))?;
        Ok(DataKey(dk))
    }
}

struct Entry {
    dk: DataKey,
    keys: DerivedKeys,
    created: Timestamp,
}

/// A profile's keyring with its data keys unwrapped: the software [`Sealer`].
pub struct Keyring<R> {
    profile_id: [u8; 16],
    current: Kid,
    index: Kid,
    entries: BTreeMap<Kid, Entry>,
    random: R,
}

impl<R> core::fmt::Debug for Keyring<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("current", &self.current)
            .field("index", &self.index)
            .field("kids", &self.entries.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

fn random_kid(random: &impl Random) -> Result<Kid, StoreError> {
    // keys.md: identifiers come from the CSPRNG, never from time.
    let mut b = [0u8; 8];
    random.fill(&mut b)?;
    let mut s = String::from("k-");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    Kid::new(&s)
}

fn random_dk(random: &impl Random) -> Result<DataKey, StoreError> {
    let mut b = Zeroizing::new([0u8; 32]);
    random.fill(b.as_mut_slice())?;
    Ok(DataKey(b))
}

impl<R: Random> Keyring<R> {
    /// Unwraps every data key of `file` (STORE-063, STORE-064).
    ///
    /// # Errors
    ///
    /// The wrapper's errors; `unsupported_version` for an entry of another wrapper.
    pub async fn open<W: KeyWrapper>(
        file: &KeyringFile,
        wrapper: &W,
        random: R,
    ) -> Result<Self, StoreError> {
        let mut entries = BTreeMap::new();
        for e in &file.entries {
            if e.wrapper_id != wrapper.id() {
                return Err(StoreError::UnsupportedVersion("wrapper"));
            }
            let dk = wrapper.unwrap(&file.profile_id, &e.kid, &e.wrapped).await?;
            let keys = derive(&dk);
            entries.insert(
                e.kid.clone(),
                Entry {
                    dk,
                    keys,
                    created: e.created,
                },
            );
        }
        Ok(Keyring {
            profile_id: file.profile_id,
            current: file.current_kid.clone(),
            index: file.index_kid.clone(),
            entries,
            random,
        })
    }

    /// A new keyring with a random profile id and one data key that is current and index
    /// key (STORE-061, STORE-095), and its file.
    ///
    /// # Errors
    ///
    /// The random source's and the wrapper's errors.
    pub async fn create<W: KeyWrapper>(
        wrapper: &W,
        random: R,
        now: Timestamp,
    ) -> Result<(Self, KeyringFile), StoreError> {
        let mut profile_id = [0u8; 16];
        random.fill(&mut profile_id)?;
        let kid = random_kid(&random)?;
        let dk = random_dk(&random)?;
        let protected = wrapper.wrap(&profile_id, &kid, &dk).await?;
        let file = KeyringFile {
            profile_id,
            current_kid: kid.clone(),
            index_kid: kid.clone(),
            entries: vec![WrappedKey {
                kid: kid.clone(),
                created: now,
                wrapper_id: wrapper.id().to_owned(),
                wrapped: protected,
            }],
        };
        let keys = derive(&dk);
        let entries = BTreeMap::from([(
            kid.clone(),
            Entry {
                dk,
                keys,
                created: now,
            },
        )]);
        Ok((
            Keyring {
                profile_id,
                current: kid.clone(),
                index: kid,
                entries,
                random,
            },
            file,
        ))
    }

    /// STORE-043: adds a new data key and makes it current; records under older kids stay
    /// readable. Returns the new file.
    ///
    /// # Errors
    ///
    /// `limit_exceeded` with 256 keys already; the random source's and the wrapper's errors.
    pub async fn rotate<W: KeyWrapper>(
        &mut self,
        file: &KeyringFile,
        wrapper: &W,
        now: Timestamp,
    ) -> Result<KeyringFile, StoreError> {
        if file.entries.len() >= 256 {
            return Err(StoreError::LimitExceeded("keyring"));
        }
        let kid = random_kid(&self.random)?;
        let dk = random_dk(&self.random)?;
        let protected = wrapper.wrap(&self.profile_id, &kid, &dk).await?;
        let mut next = file.clone();
        next.entries.push(WrappedKey {
            kid: kid.clone(),
            created: now,
            wrapper_id: wrapper.id().to_owned(),
            wrapped: protected,
        });
        next.current_kid = kid.clone();
        let keys = derive(&dk);
        self.entries.insert(
            kid.clone(),
            Entry {
                dk,
                keys,
                created: now,
            },
        );
        self.current = kid;
        Ok(next)
    }

    /// STORE-127: the same keyring wrapped by another wrapper; records are not touched.
    ///
    /// # Errors
    ///
    /// The wrapper's errors.
    pub async fn rewrap<W: KeyWrapper>(&self, wrapper: &W) -> Result<KeyringFile, StoreError> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for (kid, e) in &self.entries {
            let protected = wrapper.wrap(&self.profile_id, kid, &e.dk).await?;
            entries.push(WrappedKey {
                kid: kid.clone(),
                created: e.created,
                wrapper_id: wrapper.id().to_owned(),
                wrapped: protected,
            });
        }
        Ok(KeyringFile {
            profile_id: self.profile_id,
            current_kid: self.current.clone(),
            index_kid: self.index.clone(),
            entries,
        })
    }

    /// The kid that seals new records.
    pub fn current_kid(&self) -> &Kid {
        &self.current
    }

    /// When the current kid was created, for STORE-058's yearly rotation.
    pub fn current_created(&self) -> Timestamp {
        self.entries[&self.current].created
    }

    fn index_keys(&self) -> &DerivedKeys {
        &self.entries[&self.index].keys
    }
}

impl<R: Random> Sealer for Keyring<R> {
    fn profile_id(&self) -> &[u8; 16] {
        &self.profile_id
    }

    fn name(&self, ns: &Namespace, id: &[u8]) -> Result<Name, StoreError> {
        self.index_keys().name(ns, id)
    }

    fn tag(&self, ns: &Namespace, field: &Field, value: &[u8]) -> Result<Tag, StoreError> {
        self.index_keys().tag(ns, field, value)
    }

    fn seal(
        &self,
        ns: &Namespace,
        name: &Name,
        not_after: Option<Timestamp>,
        payload: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0u8; 12];
        self.random.fill(&mut nonce)?;
        let keys = &self.entries[&self.current].keys;
        seal_record(
            keys.value_key(),
            &self.profile_id,
            &self.current,
            ns,
            name,
            not_after,
            &nonce,
            payload,
        )
    }

    fn open(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
        record: &[u8],
    ) -> Result<Opened, StoreError> {
        open_sealed(
            |kid| self.entries.get(kid).map(|e| e.keys.value_key()),
            &self.profile_id,
            ns,
            name,
            now,
            record,
        )
    }
}
