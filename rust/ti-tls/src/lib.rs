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

//! TLS server verification for TI clients, under the profiles of `spec/pki-validation`:
//!
//! - `ti` for servers of the Telematikinfrastruktur: their trust is the TI's own, judged by
//!   [`ti_pki::tls::ServerCheck`];
//! - `web` for servers on the internet: the host system's roots, with the requirements
//!   gematik and the ZETA SDK add ([`web::WebCheck`]).
//!
//! The profile is the endpoint's, by configuration, never inferred from what a server
//! presents (TLSV-001), and neither falls back to the other.
//!
//! A Konnektor is verified by neither: [`konnektor`] holds the trust its `.kon` file
//! configures.
#![forbid(unsafe_code)]

pub mod algorithms;
mod block;
pub mod fetch;
pub mod konnektor;
pub mod verdict;
pub mod verifier;
pub mod web;

pub use fetch::{Fetch, Offline};
pub use verdict::{Code, StatusSource, Verdict};
pub use verifier::{TiVerifier, WarningObserver, WebVerifier, client_config};
pub use web::WebCheck;
