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

//! The HTTP client of the commands: ti-client's, made from the curl-like options of
//! [`NetArgs`], with `-v` lines on stderr.

use std::sync::Arc;

use ti_client::Client;
use ti_client::http::Http;

use crate::error::CliError;
use crate::net::NetArgs;
use crate::output::{Output, diagnostic};

/// The client of `net`, telling `-v` about each download and OCSP request.
pub fn client(net: &NetArgs, verbose: u8) -> Client {
    let client = Client::new(net.net());
    if verbose >= 1 {
        client.observed(Arc::new(|message| diagnostic(message)))
    } else {
        client
    }
}

/// The transport for downloads and OCSP. `-k` skips the TLS check for downloads only: the
/// TSL and roots.json are verified by their content, and the report says so.
pub fn transport(net: &NetArgs, verbose: u8) -> Result<Http, CliError> {
    Ok(client(net, verbose).downloads()?)
}

/// The IDP-Dienst's agent ([`ti_client::http::idp_agent`]) as a
/// [`ti_idpd_client::http::Transport`] and a [`ti_directory_client::http::Transport`], with
/// one `-v` line per request.
pub struct Logged<'a> {
    inner: ti_client::http::UreqTransport,
    out: &'a Output,
}

impl<'a> Logged<'a> {
    /// The transport over the IDP-Dienst's agent.
    pub fn new(net: &NetArgs, out: &'a Output) -> Result<Logged<'a>, CliError> {
        Ok(Logged {
            inner: client(net, 0).idp()?,
            out,
        })
    }

    fn log(&self, method: impl std::fmt::Display, url: &str, response: Result<(u16, &[u8]), &str>) {
        match response {
            Ok((status, body)) => {
                self.out.verbose(
                    1,
                    format_args!("{method} {url} → {status} ({} bytes)", body.len()),
                );
                if !(200..400).contains(&status) && !body.is_empty() {
                    self.out
                        .verbose(2, String::from_utf8_lossy(body).trim_end());
                }
            }
            Err(e) => self.out.verbose(1, format_args!("{method} {url} → {e}")),
        }
    }
}

impl ti_idpd_client::http::Transport for Logged<'_> {
    async fn send(
        &self,
        request: &ti_idpd_client::http::Request,
    ) -> Result<ti_idpd_client::http::Response, ti_idpd_client::http::TransportError> {
        let response = ti_idpd_client::http::Transport::send(&self.inner, request).await;
        self.log(
            request.method,
            &request.url,
            response
                .as_ref()
                .map(|r| (r.status, r.body.as_slice()))
                .map_err(|e| e.0.as_str()),
        );
        response
    }
}

/// The directory's requests go the IDP-Dienst's way: the same agent, the same log lines.
impl ti_directory_client::http::Transport for Logged<'_> {
    async fn send(
        &self,
        request: &ti_directory_client::http::Request,
    ) -> Result<ti_directory_client::http::Response, ti_directory_client::http::TransportError>
    {
        let response = ti_directory_client::http::Transport::send(&self.inner, request).await;
        self.log(
            request.method,
            &request.url,
            response
                .as_ref()
                .map(|r| (r.status, r.body.as_slice()))
                .map_err(|e| e.0.as_str()),
        );
        response
    }
}
