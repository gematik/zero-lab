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

//! Any bytes as the IDP-Dienst's discovery document, which is parsed before its signature is checked:
//! it errors or yields metadata whose signed issuer is the IDP asked. The seed is the reference IDP's
//! published document, so the fuzzer reaches the signature and validity checks.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ti_idpd_client::http::Response;
use ti_idpd_client::trust::Unverified;
use ti_idpd_client::{Env, Idp, discovery};
use ti_types::Timestamp;

/// The capture time of the seeds: the reference IDP's discovery document is valid then.
const NOW: Timestamp = Timestamp(1_793_910_924);

/// `parse` waits only on the trust check, which `Unverified` answers at once.
fn ready<F: Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match std::pin::pin!(future).poll(&mut context) {
        std::task::Poll::Ready(output) => output,
        std::task::Poll::Pending => unreachable!("Unverified never waits"),
    }
}

fn ok(body: &[u8]) -> Response {
    Response {
        status: 200,
        headers: Vec::new(),
        body: body.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    let idp = Idp::for_env(Env::Ref);
    if let Ok(found) = ready(discovery::parse(&idp, &ok(data), || NOW, &Unverified)) {
        assert_eq!(found.metadata.issuer.trim_end_matches('/'), idp.base_url());
    }
});
