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

//! The store facade over the memory backend: what the corpus does not reach because it
//! needs a keyring, a namespace registry or several steps.

#![cfg(feature = "store")]

use futures_lite::future::block_on;
use ti_store::store::registry::{self, NamespaceSpec};
use ti_store::store::{
    Backend, Capabilities, KeyFileWrapper, Keyring, KeyringFile, MemoryBackend, OsRandom, Sealer,
    Store, StoreError,
};
use ti_types::Timestamp;
use zeroize::Zeroizing;

const NOW: Timestamp = Timestamp(1_767_225_600);

fn wrapper(kek: u8) -> KeyFileWrapper<OsRandom> {
    KeyFileWrapper::new(Zeroizing::new([kek; 32]), OsRandom)
}

fn keyring() -> (Keyring<OsRandom>, KeyringFile) {
    block_on(Keyring::create(&wrapper(1), OsRandom, NOW)).expect("keyring")
}

fn store() -> Store<MemoryBackend, Keyring<OsRandom>> {
    Store::new(MemoryBackend::new(), Some(keyring().0), registry::ALL).expect("store")
}

fn later(secs: u64) -> Timestamp {
    Timestamp(NOW.0 + secs)
}

/// STORE-055: a sealed record comes back as it went in, and its id and payload are not in
/// what the backend holds (STORE-030, STORE-036).
#[test]
fn store_055_sealed_records_round_trip_and_hide_ids_and_payloads() {
    let s = store();
    let id = b"TEST-ONLY-KVNR-0001";
    let name = block_on(s.put(
        &registry::POPP,
        id,
        b"TEST-ONLY PoPP token",
        &[("kvnr", id)],
        Some(later(3600)),
        NOW,
    ))
    .unwrap();
    let got = block_on(s.get(&registry::POPP, id, NOW)).unwrap();
    assert_eq!(got.payload.as_slice(), b"TEST-ONLY PoPP token");
    assert_eq!(got.expires_at, Some(later(3600)));
    assert_eq!(got.name, name);

    let ns = ti_store::store::Namespace::new("popp").unwrap();
    let raw = block_on(s.backend().get(&ns, &name, NOW)).unwrap();
    for secret in [&id[..], b"PoPP token"] {
        assert!(
            !raw.value.windows(secret.len()).any(|w| w == secret),
            "the backend sees a secret in clear"
        );
        assert!(
            !raw.tags
                .iter()
                .any(|t| t.tag.windows(secret.len()).any(|w| w == secret))
        );
    }
}

/// STORE-035, STORE-015: query by indexed metadata.
#[test]
fn store_015_query_finds_records_by_metadata() {
    let s = store();
    for (id, kvnr) in [(&b"a"[..], &b"K1"[..]), (b"b", b"K1"), (b"c", b"K2")] {
        block_on(s.put(
            &registry::POPP,
            id,
            id,
            &[("kvnr", kvnr)],
            Some(later(60)),
            NOW,
        ))
        .unwrap();
    }
    let (found, cursor) =
        block_on(s.query(&registry::POPP, &[("kvnr", b"K1")], 10, None, NOW)).unwrap();
    let mut payloads: Vec<_> = found.iter().map(|r| r.payload.to_vec()).collect();
    payloads.sort();
    assert_eq!(payloads, vec![b"a".to_vec(), b"b".to_vec()]);
    assert!(cursor.is_none());
}

/// STORE-023: without a keyring, sealed namespaces are refused and plain ones work.
#[test]
fn store_023_without_a_keyring_sealed_namespaces_are_refused() {
    let s: Store<MemoryBackend, Keyring<OsRandom>> =
        Store::new(MemoryBackend::new(), None, registry::ALL).unwrap();
    let err = block_on(s.put(&registry::TSL_STATE, b"tsl", b"42", &[], None, NOW)).unwrap_err();
    assert_eq!(err, StoreError::NoKeyring);
    assert_eq!(
        block_on(s.get(&registry::POPP, b"x", NOW)).unwrap_err(),
        StoreError::NoKeyring
    );
    block_on(s.put(
        &registry::WELL_KNOWN,
        b"https://idp.example.test",
        b"{}",
        &[],
        Some(later(60)),
        NOW,
    ))
    .unwrap();
    assert_eq!(
        block_on(s.get(&registry::WELL_KNOWN, b"https://idp.example.test", NOW))
            .unwrap()
            .payload
            .as_slice(),
        b"{}"
    );
}

/// STORE-022: a namespace's lifetime bounds its records, and only its fields are indexed.
#[test]
fn store_022_lifetimes_and_fields_follow_the_registry() {
    let s = store();
    let put =
        |exp, meta: &[(&str, &[u8])]| block_on(s.put(&registry::POPP, b"x", b"p", meta, exp, NOW));
    assert!(matches!(
        put(None, &[]),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        put(Some(later(86_401)), &[]),
        Err(StoreError::InvalidArgument(_))
    ));
    assert!(matches!(
        put(Some(later(60)), &[("issuer", b"x")]),
        Err(StoreError::InvalidArgument(_))
    ));
    put(Some(later(86_400)), &[("iccsn", b"80276")]).unwrap();
    // a namespace without a lifetime takes records without expiry
    block_on(s.put(&registry::COMFORT, b"card", b"user", &[], None, NOW)).unwrap();
}

/// STORE-019: a namespace that needs a capability refuses a backend without it.
#[test]
fn store_019_missing_capabilities_are_refused_at_construction() {
    let needs_multi = NamespaceSpec {
        requires: Capabilities {
            multi_process: true,
            ..Capabilities::default()
        },
        ..registry::POPP
    };
    let err =
        Store::<_, Keyring<OsRandom>>::new(MemoryBackend::new(), None, &[needs_multi]).unwrap_err();
    assert_eq!(err.code(), "capability_missing");
}

/// STORE-012: take hands a record out once.
#[test]
fn store_012_take_hands_a_record_out_once() {
    let s = store();
    block_on(s.put(&registry::POPP, b"x", b"p", &[], Some(later(60)), NOW)).unwrap();
    assert_eq!(
        block_on(s.take(&registry::POPP, b"x", NOW))
            .unwrap()
            .payload
            .as_slice(),
        b"p"
    );
    assert_eq!(
        block_on(s.take(&registry::POPP, b"x", NOW)).unwrap_err(),
        StoreError::NotFound
    );
}

/// STORE-043: after rotation, new records use the new kid and old ones still open.
#[test]
fn store_043_rotation_keeps_older_records_readable() {
    let (mut ring, file) = keyring();
    let old_kid = ring.current_kid().clone();
    let ns = ti_store::store::Namespace::new("popp").unwrap();
    let name = ring.name(&ns, b"x").unwrap();
    let old = ring.seal(&ns, &name, Some(later(60)), b"old").unwrap();
    block_on(ring.rotate(&file, &wrapper(1), NOW)).unwrap();
    assert_ne!(ring.current_kid(), &old_kid);
    let new = ring.seal(&ns, &name, Some(later(60)), b"new").unwrap();
    assert_eq!(
        ring.open(&ns, &name, NOW, &old).unwrap().kid.as_ref(),
        Some(&old_kid)
    );
    assert_eq!(
        ring.open(&ns, &name, NOW, &new).unwrap().payload.as_slice(),
        b"new"
    );
    // names come from the index kid, which rotation leaves alone
    assert_eq!(ring.name(&ns, b"x").unwrap(), name);
}

/// STORE-127, STORE-064: rewrapping changes only the wrapping; the old key file no longer
/// opens the new keyring.
#[test]
fn store_127_rewrap_moves_the_keyring_to_a_new_key_file() {
    let (ring, file) = keyring();
    let ns = ti_store::store::Namespace::new("comfort").unwrap();
    let name = ring.name(&ns, b"card").unwrap();
    let record = ring.seal(&ns, &name, None, b"user").unwrap();

    let moved = block_on(ring.rewrap(&wrapper(2))).unwrap();
    assert_eq!(moved.profile_id, file.profile_id);
    let reopened = block_on(Keyring::open(
        &KeyringFile::parse(&moved.encode()).unwrap(),
        &wrapper(2),
        OsRandom,
    ))
    .unwrap();
    assert_eq!(
        reopened
            .open(&ns, &name, NOW, &record)
            .unwrap()
            .payload
            .as_slice(),
        b"user"
    );
    let err = block_on(Keyring::open(&moved, &wrapper(1), OsRandom)).unwrap_err();
    assert_eq!(err.code(), "auth_failed");
}

/// STORE-061: every keyring has its own profile id, so records do not move between
/// profiles (STORE-055).
#[test]
fn store_061_records_do_not_open_in_another_profile() {
    let (a, _) = keyring();
    let (b, _) = keyring();
    assert_ne!(a.profile_id(), b.profile_id());
    let ns = ti_store::store::Namespace::new("popp").unwrap();
    let name = a.name(&ns, b"x").unwrap();
    let record = a.seal(&ns, &name, Some(later(60)), b"p").unwrap();
    assert!(b.open(&ns, &name, NOW, &record).is_err());
}
