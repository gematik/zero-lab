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

//! Any text as the `Location` of the FHIR-Directory's owner-authenticate redirect: it errors or yields
//! that location, which goes to the directory's own IDP-Dienst.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_directory::http::Response;
use ti_directory::{Directory, Env, owner};

fuzz_target!(|data: &[u8]| {
    let location = String::from_utf8_lossy(data).into_owned();
    let response = Response {
        status: 302,
        headers: vec![("Location".to_owned(), location.clone())],
        body: Vec::new(),
    };
    if let Ok(url) = owner::authorization_url(&Directory::for_env(Env::Ref), &response) {
        assert_eq!(url, location);
    }
});
