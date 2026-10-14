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

//! A blocking [`Transport`] over ureq 3 (feature `ureq`).

use crate::http::{Method, Request, Response, Transport, TransportError};

/// Largest body read; discovery documents, keys and challenges are a few KiB.
const MAX_BODY: u64 = 1024 * 1024;

/// ureq as the flow's transport. The agent must be configured with
/// `max_redirects(0)` and `http_status_as_error(false)`: a redirect and a 4xx are
/// answers here, not failures. [`UreqTransport::agent`] builds one such from a config
/// builder.
#[derive(Clone, Debug)]
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// Over `agent`, configured as the type's documentation says.
    pub fn new(agent: ureq::Agent) -> UreqTransport {
        UreqTransport { agent }
    }

    /// `builder` finished the way the flow needs it: no redirects followed, statuses
    /// never errors.
    pub fn agent(builder: ureq::config::ConfigBuilder<ureq::typestate::AgentScope>) -> ureq::Agent {
        builder
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .new_agent()
    }
}

impl Transport for UreqTransport {
    fn send(&self, request: &Request) -> Result<Response, TransportError> {
        let failed = |e: ureq::Error| TransportError(e.to_string());
        let mut response = match request.method {
            Method::Get => {
                let mut req = self.agent.get(&request.url);
                for (name, value) in &request.headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                req.call().map_err(failed)?
            }
            Method::Post => {
                let mut req = self.agent.post(&request.url);
                for (name, value) in &request.headers {
                    req = req.header(name.as_str(), value.as_str());
                }
                req.send(&request.body[..]).map_err(failed)?
            }
        };
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(failed)?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}
