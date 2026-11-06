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

use crate::http::{Request, Response, Transport, TransportError};

/// ureq as the source's transport. The agent must be configured with `max_redirects(0)`
/// and `http_status_as_error(false)`: a redirect and a 304 are answers here, not failures.
/// [`UreqTransport::agent`] builds one such from a config builder, which carries the
/// host's TLS, proxy and timeouts.
#[derive(Clone, Debug)]
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    /// Over `agent`, configured as the type's documentation says.
    pub fn new(agent: ureq::Agent) -> UreqTransport {
        UreqTransport { agent }
    }

    /// `builder` finished the way the source needs it: no redirects followed, statuses
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
    async fn get(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        let failed = |e: ureq::Error| TransportError(e.to_string());
        let mut req = self.agent.get(request.url);
        for (name, value) in &request.headers {
            req = req.header(*name, value.as_str());
        }
        let mut response = req.call().map_err(failed)?;
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
            .limit(request.max_body)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(limit) => {
                    TransportError(format!("body longer than {limit} bytes"))
                }
                e => failed(e),
            })?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}
