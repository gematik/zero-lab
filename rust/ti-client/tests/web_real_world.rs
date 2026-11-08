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

//! gematik's internet endpoints under the `web` profile, live: the system's roots, OCSP and CRLs
//! fetched for real. Network required, so not part of `just check`:
//! `cargo test -p ti-client --test web_real_world -- --ignored`.

use std::sync::Arc;

use ti_client::tls::{UreqFetch, agent};
use ti_tls::{WebCheck, WebVerifier, client_config};

/// The TSL download points, the IDP-Dienst and the FHIR-Directory with its Keycloak: each
/// handshake verifies under `web`, and an unknown name does not.
#[test]
#[ignore = "network"]
fn tlsv_040_gematiks_internet_endpoints_verify_under_web() {
    let plain = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .new_agent();
    let verifier = WebVerifier::new(WebCheck::system(), UreqFetch::new(plain));
    let https = agent(
        ureq::Agent::config_builder(),
        Arc::new(client_config(Arc::new(verifier))),
    );
    for url in [
        "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
        "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
        "https://idp.app.ti-dienste.de/.well-known/openid-configuration",
        "https://idp-ref.app.ti-dienste.de/.well-known/openid-configuration",
        "https://idp-test.app.ti-dienste.de/.well-known/openid-configuration",
        "https://fhir-directory.vzd.ti-dienste.de/",
        "https://auth.vzd.ti-dienste.de:9443/",
    ] {
        let response = https.get(url).call();
        assert!(response.is_ok(), "{url}: {:?}", response.err());
    }
}
