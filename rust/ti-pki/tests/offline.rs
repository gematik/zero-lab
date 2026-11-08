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

//! The offline check against the published production TSL of
//! `spec/tsl-detached/testdata`, at the instant it was captured, so every result is
//! deterministic.
#![cfg(all(feature = "load", feature = "brainpool", feature = "rsa"))]

use std::path::PathBuf;

use ti_pki::offline::{Check, Outcome, ProfileChoice, RootsSource};
use ti_pki::profile::SelectReason;
use ti_pki::{Certificate, Env, Timestamp, TrustConfig, parse_pem_certificates};

/// The capture time of the published sets in `spec/tsl-detached/testdata`.
const NOW: &str = "2026-11-01T16:47:42Z";

fn now() -> Timestamp {
    Timestamp::parse_rfc3339(NOW).unwrap()
}

fn read(path: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn prod(suffix: &str) -> Vec<u8> {
    read(&format!(
        "../../spec/tsl-detached/testdata/prod/ECC-RSA_TSL.{suffix}"
    ))
}

/// The TEST-ONLY SMC-B end-entity certificate of the fixtures.
fn smcb() -> Certificate {
    parse_pem_certificates(&read("tests/fixtures/smcb-ee-test-only.pem"))
        .unwrap()
        .remove(0)
}

fn context(xml: &[u8], roots: Option<&[u8]>) -> Check {
    Check::new(
        Env::Prod,
        TrustConfig::preset_prod(),
        roots,
        xml,
        &prod("sig"),
        now(),
    )
}

#[test]
fn a_check_against_the_production_tsl_reports_its_trust_material() {
    let context = context(&prod("xml"), None);
    assert_eq!(context.env(), Env::Prod);
    let material = context.material();
    assert_eq!(material.roots_source, RootsSource::Embedded);
    assert!(material.roots_warning.is_none());
    let verified = material.tsl.as_ref().unwrap();
    assert!(verified.tsl.sequence_number > 0);

    // A TEST-ONLY certificate has no place in production.
    let cert = smcb();
    let outcome = context.check(std::slice::from_ref(&cert), now());
    let Outcome::Validated { profile, result } = outcome else {
        panic!("validated against a verified TSL: {outcome:?}");
    };
    let ProfileChoice::Detected {
        profile,
        cert_type,
        reason,
        ..
    } = profile
    else {
        panic!("an SMC-B has a profile: {profile:?}");
    };
    assert_eq!(
        (profile.name, cert_type.as_str(), reason),
        ("hci-aut", "C.HCI.AUT", SelectReason::ByDefault)
    );
    let result = result.unwrap();
    assert!(!result.valid);
    assert!(!result.errors.is_empty());
    assert_eq!(result.chain.first(), Some(&cert));
}

#[test]
fn a_check_against_an_invalid_tsl_trusts_nothing() {
    let mut xml = prod("xml");
    let at = xml.len() / 2;
    xml[at] ^= 0x01;
    let context = context(&xml, None);
    let error = context.material().tsl.as_ref().unwrap_err();
    assert_eq!(error.tsl.as_ref().unwrap().rule, "TSLDET-005");

    assert!(matches!(
        context.check(&[smcb()], now()),
        Outcome::Untrusted
    ));
}

/// A roots.json that does not walk from the anchor falls back to the embedded roots, and
/// the check says why.
#[test]
fn unusable_supplied_roots_fall_back_to_the_embedded_ones_with_a_warning() {
    let context = context(&prod("xml"), Some(b"[]"));
    let material = context.material();
    assert!(material.tsl.is_ok());
    assert_eq!(material.roots_source, RootsSource::Embedded);
    assert!(
        material
            .roots_warning
            .as_deref()
            .is_some_and(|w| w.starts_with("supplied roots.json: "))
    );
}

/// Supplied roots that walk from the anchor are the ones used.
#[test]
fn usable_supplied_roots_are_used() {
    let roots = TrustConfig::preset_prod().roots.into_owned();
    let context = context(&prod("xml"), Some(&roots));
    let material = context.material();
    assert!(material.tsl.is_ok());
    assert_eq!(material.roots_source, RootsSource::Supplied);
    assert!(material.roots_warning.is_none());
}
