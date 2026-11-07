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

//! [`Client`]: the transports a front end needs, made from one set of HTTP settings.

use core::fmt;

use ti_connector_client::Dotkon;

use crate::connector;
use crate::http::{self, Http, Observer};
use crate::net::{Error, Net};

/// The host's HTTP settings and the observer of its requests, from which every transport
/// is made. Send and Sync, so a desktop app can share it between the threads its commands
/// block on; nothing in it is async.
#[derive(Clone)]
pub struct Client {
    net: Net,
    observer: Option<Observer>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("net", &self.net)
            .field("observed", &self.observer.is_some())
            .finish()
    }
}

impl Client {
    /// A client with `net`'s settings and no observer.
    pub fn new(net: Net) -> Client {
        Client {
            net,
            observer: None,
        }
    }

    /// The client with `observer` told about each download and OCSP request.
    #[must_use]
    pub fn observed(mut self, observer: Observer) -> Client {
        self.observer = Some(observer);
        self
    }

    /// The HTTP settings.
    pub fn net(&self) -> &Net {
        &self.net
    }

    /// ti-pki's transport for downloads and OCSP ([`http::transport`]).
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for an unusable proxy or CA file or directory.
    pub fn downloads(&self) -> Result<Http, Error> {
        http::transport(&self.net, self.observer.clone())
    }

    /// The transport of the IDP-Dienst and the FHIR-Directory ([`http::idp_agent`]).
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for an unusable proxy or CA file or directory.
    pub fn idp(&self) -> Result<http::UreqTransport, Error> {
        Ok(http::UreqTransport::new(http::idp_agent(&self.net)?))
    }

    /// The transport of the Konnektor `dotkon` configures ([`connector::agent_config`]).
    ///
    /// # Errors
    ///
    /// [`Error::Setup`] for an unusable proxy, [`Error::Connector`] for unusable credentials
    /// or trust store.
    pub fn connector(&self, dotkon: &Dotkon) -> Result<connector::UreqTransport, Error> {
        connector::UreqTransport::new(dotkon, connector::agent_config(&self.net)?)
            .map_err(Error::Connector)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_is_shared_between_threads() {
        fn send_and_sync<T: Send + Sync>() {}
        send_and_sync::<Client>();
    }
}
