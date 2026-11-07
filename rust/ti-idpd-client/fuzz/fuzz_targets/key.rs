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

//! Any bytes as one of the IDP-Dienst's keys (`uri_puk_idp_sig`, `uri_puk_idp_enc`): it errors or
//! yields a JWK, never panics. The seeds are the reference IDP's published keys.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_idpd_client::discovery;
use ti_idpd_client::http::Response;

fuzz_target!(|data: &[u8]| {
    let response = Response {
        status: 200,
        headers: Vec::new(),
        body: data.to_vec(),
    };
    let _ = discovery::parse_key("PuK_IDP_SIG", &response);
});
