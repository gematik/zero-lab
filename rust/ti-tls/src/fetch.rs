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

//! What a check asks of the network: an OCSP responder or a CRL host. The host performs it,
//! with its own client, proxy and timeouts, over plain HTTP as both are published.

/// Fetches revocation material. No `Send` bound, so a single-threaded host can implement it;
/// `None` is "did not answer", which the checks treat as no source.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Fetch {
    /// The DER response of the responder at `url` to the DER OCSP `request`, POSTed.
    async fn ocsp(&self, url: &str, request: &[u8]) -> Option<Vec<u8>>;
    /// The DER CRL at `url`.
    async fn crl(&self, url: &str) -> Option<Vec<u8>>;
}

impl<F: Fetch + ?Sized> Fetch for &F {
    async fn ocsp(&self, url: &str, request: &[u8]) -> Option<Vec<u8>> {
        (**self).ocsp(url, request).await
    }

    async fn crl(&self, url: &str) -> Option<Vec<u8>> {
        (**self).crl(url).await
    }
}

/// A fetcher that never answers: every revocation source is down.
#[derive(Clone, Copy, Debug, Default)]
pub struct Offline;

impl Fetch for Offline {
    async fn ocsp(&self, _: &str, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    async fn crl(&self, _: &str) -> Option<Vec<u8>> {
        None
    }
}
