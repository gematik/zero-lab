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

//! Any text as the IDP-Dienst's redirect with the code, turned into the request to the directory's
//! sign-in: it errors, or the request goes to the directory's sign-in endpoint and nowhere else.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_directory::http::Response;
use ti_directory::{Directory, Env, owner};
use ti_idpd::challenge;

fuzz_target!(|data: &[u8]| {
    let response = Response {
        status: 302,
        headers: vec![("Location".to_owned(), String::from_utf8_lossy(data).into_owned())],
        body: Vec::new(),
    };
    let Ok(redirect) = challenge::code(&response) else {
        return;
    };
    let directory = Directory::for_env(Env::Ref);
    if let Ok(request) = owner::sign_in(&directory, &redirect) {
        // A host name is the same in any case (RFC 3986 section 3.2.2).
        assert!(
            request
                .url
                .to_ascii_lowercase()
                .starts_with(directory.base_url()),
            "the code went to {}",
            request.url
        );
    }
});
