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

//! Any bytes as a roots.json, which comes from the network before any signature is checked: parsing
//! errors or yields entries, and the A_28419 walk over them from the embedded anchor errors or
//! starts at that anchor. The seeds are gematik's published files, so the fuzzer reaches the cross
//! certificates the walk decodes.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use ti_pki::{Certificate, Timestamp, algorithms, anchors, roots};

static ANCHOR: LazyLock<Certificate> = LazyLock::new(|| {
    Certificate::from_der(anchors::GEM_RCA7_TEST_ONLY).expect("the embedded anchor parses")
});
/// A time inside the validity of the published roots.
const NOW: Timestamp = Timestamp(1_793_638_062);

fuzz_target!(|data: &[u8]| {
    let Ok(entries) = roots::parse(data) else {
        return;
    };
    assert!(!entries.is_empty(), "parse accepts no empty list");
    if let Ok(walk) = roots::walk(&ANCHOR, &entries, NOW, algorithms::DEFAULT) {
        assert!(
            walk.trusted.first() == Some(&*ANCHOR),
            "the walk does not start at the anchor"
        );
    }
});
