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
//! supplied roots never break or widen trust, so the report stays the one of the embedded roots.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use ti_wasm::api;

const XML: &[u8] = include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.xml");
const SIGNATURE: &[u8] = include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.sig");
const SIGNER_STATUS: &[u8] =
    include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.ocsp");
/// The capture time of the published set (spec/tsl-detached/testdata/README.md).
const NOW: &str = "2026-11-02T16:47:42Z";
const VALID: &str = "\"result\":\"valid\"";

static EMBEDDED: LazyLock<bool> = LazyLock::new(|| {
    api::verify_tsl(XML, SIGNATURE, Some(SIGNER_STATUS), "ref", NOW, None, 0)
        .expect("fixed inputs")
        .contains(VALID)
});

fuzz_target!(|data: &[u8]| {
    assert!(*EMBEDDED, "the published set does not verify at NOW: the target would prove nothing");
    let report = api::verify_tsl(XML, SIGNATURE, Some(SIGNER_STATUS), "ref", NOW, Some(data), 0)
        .expect("environment, time and grace are fixed and valid");
    assert_eq!(report.contains(VALID), *EMBEDDED, "the supplied roots changed the verdict");
});
