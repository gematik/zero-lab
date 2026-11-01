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

//! Any bytes as the signer's OCSP response file (TSLDET-020): checked against the
//! reference signer and its CA, it errors or answers, never panics. The published
//! response is the seed, so the fuzzer reaches the signature and certHash checks.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use ti_pki::ocsp::{ResponseCheck, verify_response};
use ti_pki::{Certificate, Timestamp, algorithms};

static SIGNER: LazyLock<Certificate> = LazyLock::new(|| {
    let sig = include_bytes!("../../../../spec/tsl-detached/testdata/ref/ECC-RSA_TSL-ref.sig");
    ti_pki::tsl_signature::parse_detached_signature(sig)
        .expect("the published signature file parses")
        .signer
});
static ISSUER: LazyLock<Certificate> = LazyLock::new(|| {
    Certificate::from_der(ti_pki::anchors::GEM_TSL_CA28_TEST_ONLY).expect("the anchor parses")
});
/// The capture time of the published sets (spec/tsl-detached/testdata/README.md).
const NOW: Timestamp = Timestamp(1_793_638_062);

fuzz_target!(|data: &[u8]| {
    let check = ResponseCheck::new(NOW, algorithms::DEFAULT);
    let _ = verify_response(data, &SIGNER, &ISSUER, &check);
});
