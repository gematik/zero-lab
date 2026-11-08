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

//! ureq 3 with a ti-tls profile's verifier: a connector that does the handshake with a rustls
//! configuration from [`ti_tls::client_config`], one agent per profile, and a [`Fetch`] for the
//! `web` profile's OCSP responders and CRL hosts over plain HTTP.
//!
//! ureq's stable TLS settings take root certificates, not a verifier, so the connector uses its
//! semver-exempt `unversioned` transport API (ureq pinned `~3.5`, as for the Konnektor).

use core::fmt;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use ureq::Agent;
use ureq::config::ConfigBuilder;
use ureq::typestate::AgentScope;
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectProxyConnector, ConnectionDetails, Connector, Either, LazyBuffers, NextTimeout,
    TcpConnector, Transport, TransportAdapter,
};

use ti_tls::Fetch;

/// Largest OCSP response or CRL read: CRLs of public CAs are kilobytes to a few megabytes.
const MAX_REVOCATION_BODY: u64 = 16 * 1024 * 1024;

/// An agent from `builder` (proxy, timeouts, user agent) whose TLS is `config`'s: every https
/// connection is verified by the profile's verifier in it. Statuses are never errors.
pub fn agent(builder: ConfigBuilder<AgentScope>, config: Arc<ClientConfig>) -> Agent {
    let connector =
        ().chain(ConnectProxyConnector::default())
            .chain(TcpConnector::default())
            .chain(Rustls { config });
    Agent::with_parts(
        builder.http_status_as_error(false).build(),
        connector,
        DefaultResolver::default(),
    )
}

/// The `web` profile's revocation sources over `agent`, which needs no TLS: OCSP and CRL
/// addresses are plain HTTP.
#[derive(Clone, Debug)]
pub struct UreqFetch {
    agent: Agent,
}

impl UreqFetch {
    /// Fetches through `agent`.
    pub fn new(agent: Agent) -> UreqFetch {
        UreqFetch { agent }
    }

    fn body(response: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Option<Vec<u8>> {
        let mut response = response.ok()?;
        if !response.status().is_success() {
            return None;
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_REVOCATION_BODY)
            .read_to_vec()
            .ok()
    }
}

impl Fetch for UreqFetch {
    async fn ocsp(&self, url: &str, request: &[u8]) -> Option<Vec<u8>> {
        UreqFetch::body(
            self.agent
                .post(url)
                .header("Content-Type", ti_pki::ocsp::CONTENT_TYPE_REQUEST)
                .header("Accept", ti_pki::ocsp::CONTENT_TYPE_RESPONSE)
                .send(request),
        )
    }

    async fn crl(&self, url: &str) -> Option<Vec<u8>> {
        UreqFetch::body(self.agent.get(url).call())
    }
}

/// The handshake, with the server name from the request's host.
struct Rustls {
    config: Arc<ClientConfig>,
}

impl<In: Transport> Connector<In> for Rustls {
    type Out = Either<In, Tls>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Ok(None);
        };
        if !details.needs_tls() || transport.is_tls() {
            return Ok(Some(Either::A(transport)));
        }
        let host = details.uri.host().unwrap_or_default();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let name = ServerName::try_from(host.to_owned())
            .map_err(|_| ureq::Error::Tls("invalid server name"))?;
        let mut conn = ClientConnection::new(Arc::clone(&self.config), name)?;
        let mut sock = TransportAdapter::new(transport.boxed(), details.current_time.clone());
        sock.set_timeout(details.timeout);
        conn.complete_io(&mut sock)?;
        Ok(Some(Either::B(Tls {
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: StreamOwned { conn, sock },
        })))
    }
}

impl fmt::Debug for Rustls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rustls").finish_non_exhaustive()
    }
}

struct Tls {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter>,
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tls").finish_non_exhaustive()
    }
}

impl Transport for Tls {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}
