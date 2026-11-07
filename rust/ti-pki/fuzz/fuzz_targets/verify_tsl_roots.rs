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

//! Any bytes as the roots.json a web page supplies next to the reference environment's published TSL:
//! supplied roots never break or widen trust, so the verdict stays the one of the embedded roots.
#![no_main]

use std::sync::LazyLock;

use core::time::Duration;

use libfuzzer_sys::fuzz_target;
use ti_pki::offline::Tsl;
use ti_pki::tsl_signature::DetachedTsl;
use ti_pki::{Env, Timestamp, TrustConfig, model};

const XML: &[u8] = include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.xml");
const SIGNATURE: &[u8] = include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.sig");
const SIGNER_STATUS: &[u8] =
    include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.ocsp");
/// The capture time of the published set (spec/tsl-detached/testdata/README.md).
const NOW: &str = "2026-11-02T16:47:42Z";

/// The view ti-wasm's `verify_tsl` returns for the reference environment without a grace period.
fn view(xml: &[u8], roots: Option<&[u8]>) -> model::Tsl {
    let now = Timestamp::parse_rfc3339(NOW).expect("a fixed time");
    let config = TrustConfig {
        tsl_grace_period: Duration::ZERO,
        ..TrustConfig::preset(Env::Ref)
    };
    let files = DetachedTsl {
        signature: SIGNATURE,
        signer_status: Some(SIGNER_STATUS),
    };
    model::Tsl::new(Env::Ref, &Tsl::verify(xml, files, Env::Ref, &config, roots, now), now)
}

static EMBEDDED: LazyLock<&'static str> = LazyLock::new(|| view(XML, None).result);

fuzz_target!(|data: &[u8]| {
    assert_eq!(*EMBEDDED, "valid", "the published set does not verify at NOW: the target would prove nothing");
    assert_eq!(view(XML, Some(data)).result, *EMBEDDED, "the supplied roots changed the verdict");
});
