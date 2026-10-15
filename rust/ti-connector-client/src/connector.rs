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

//! [`Connector`]: a Konnektor as described by a `.kon` file and its service directory;
//! the entry point to the service facades.

use ti_store::{Cache, CacheStore, Meta};
use ti_types::Clock;

use crate::api::gematik::conn::connectorcontext20::Context;
use crate::dotkon::Dotkon;
use crate::error::Error;
use crate::sds::{ServiceDirectory, Target};
use crate::soap::{Timeouts, Transport};

/// A Konnektor, ready for calls.
#[derive(Debug)]
pub struct Connector<T> {
    transport: T,
    directory: ServiceDirectory,
    context: Context,
    authorization: Option<String>,
    timeouts: Timeouts,
}

impl<T: Transport> Connector<T> {
    /// Loads the service directory through `transport` and returns the Konnektor.
    ///
    /// # Errors
    ///
    /// When the service directory cannot be loaded or read.
    pub async fn connect(dotkon: &Dotkon, transport: T, timeouts: Timeouts) -> Result<Self, Error> {
        let authorization = dotkon.authorization();
        let target = target(dotkon, authorization.as_deref(), timeouts);
        let directory = ServiceDirectory::fetch(&transport, &target).await?;
        Ok(Self::new(dotkon, transport, directory, timeouts))
    }

    /// Like [`connect`](Self::connect), with the service directory through `cache`;
    /// also returns its metadata (source and age).
    ///
    /// # Errors
    ///
    /// When the service directory can be neither loaded nor served from the cache.
    pub async fn connect_cached<S: CacheStore, C: Clock>(
        dotkon: &Dotkon,
        transport: T,
        timeouts: Timeouts,
        cache: &Cache<S, C>,
    ) -> Result<(Self, Meta), Error> {
        let authorization = dotkon.authorization();
        let target = target(dotkon, authorization.as_deref(), timeouts);
        let (directory, meta) = ServiceDirectory::fetch_cached(&transport, &target, cache).await?;
        Ok((Self::new(dotkon, transport, directory, timeouts), meta))
    }

    /// The Konnektor with a service directory the caller already has.
    pub fn new(
        dotkon: &Dotkon,
        transport: T,
        mut directory: ServiceDirectory,
        timeouts: Timeouts,
    ) -> Self {
        if dotkon.rewrite_service_endpoints {
            directory.rewrite_endpoints(&dotkon.url);
        }
        Connector {
            transport,
            directory,
            context: Context {
                mandant_id: dotkon.mandant_id.clone(),
                client_system_id: dotkon.client_system_id.clone(),
                workplace_id: dotkon.workplace_id.clone(),
                user_id: dotkon.user_id.clone(),
            },
            authorization: dotkon.authorization(),
            timeouts,
        }
    }

    /// The service directory, endpoints rewritten if the `.kon` file asks for it.
    pub fn directory(&self) -> &ServiceDirectory {
        &self.directory
    }

    pub(crate) fn transport(&self) -> &T {
        &self.transport
    }

    pub(crate) fn context(&self) -> Context {
        self.context.clone()
    }

    pub(crate) fn authorization(&self) -> Option<&str> {
        self.authorization.as_deref()
    }

    pub(crate) fn timeouts(&self) -> Timeouts {
        self.timeouts
    }
}

fn target<'a>(
    dotkon: &'a Dotkon,
    authorization: Option<&'a str>,
    timeouts: Timeouts,
) -> Target<'a> {
    Target {
        base_url: &dotkon.url,
        authorization,
        timeout: timeouts.short,
    }
}
