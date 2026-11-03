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

//! Any bytes as a `.kon` file: the parser, the file check and the redacted view never
//! panic; the file check fails exactly when the file does not parse or is not https;
//! and the view never shows the password.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_connector_client::check::{self, Status};
use ti_connector_client::config::ConfigView;
use ti_connector_client::{Credentials, Dotkon};

fuzz_target!(|input: (&[u8], u32)| {
    let (json, mode) = input;
    let parsed = Dotkon::parse_with(json, |name| (name == "KON_PASSWORD").then(|| "fuzz-password-0815".into()));
    let step = check::file(&parsed, json, Some(mode));
    let Ok(dotkon) = &parsed else {
        assert_eq!(step.status, Status::Fail);
        return;
    };
    assert_eq!(step.status == Status::Fail, !check::is_https(dotkon));
    let shown = serde_json::to_string(&ConfigView::new(dotkon, json)).expect("serializes");
    if let Credentials::Basic { password, .. } | Credentials::Pkcs12 { password, .. } = &dotkon.credentials
        && password == "fuzz-password-0815"
    {
        assert!(!shown.contains(password.as_str()));
    }
});
