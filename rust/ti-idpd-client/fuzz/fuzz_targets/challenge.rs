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

//! Any bytes as the IDP-Dienst's challenge, parsed before its signature is checked against
//! PuK_IDP_SIG: it errors, and since no input carries the IDP's signature, it never verifies.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_idpd_client::challenge;
use ti_idpd_client::discovery;
use ti_idpd_client::http::Response;
use ti_types::Timestamp;

/// The capture time of the seeds: the reference IDP's discovery document is valid then.
const NOW: Timestamp = Timestamp(1_793_910_924);

fn ok(body: &[u8]) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    // ti-idpd-client does not export the key's type for a static; parsing the small JWK is cheap.
    let puk_idp_sig =
        discovery::parse_key("PuK_IDP_SIG", &ok(include_bytes!("../seeds/key/sig.json")))
            .expect("the reference IDP's published key parses");
    assert!(
        challenge::parse(&ok(data), &puk_idp_sig, || NOW).is_err(),
        "a challenge verified without the IDP's signature"
    );
});
