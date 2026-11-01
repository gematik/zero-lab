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

//! Any bytes as `connector.sds`: the parser never panics, what parses serializes, a
//! binding is the newest supported version the directory offers and names one of its
//! endpoints, a refusal is the true one, and after a rewrite no endpoint leaves the
//! `.kon` URL's origin, which is what `rewriteServiceEndpoints` promises. Without a
//! rewrite, a call sends nothing outside that origin, whatever the directory names.
#![no_main]

use std::cell::RefCell;
use std::sync::LazyLock;

use futures_lite::future::block_on;
use libfuzzer_sys::fuzz_target;
use ti_connector_client::{
    BINDINGS, Connector, DiscoveryError, Dotkon, Request, Response, ServiceDirectory,
    ServiceVersion, Timeouts, Transport, TransportError,
};

const ORIGIN: &str = "https://konnektor.test:8443";

static KON: LazyLock<Dotkon> = LazyLock::new(|| {
    let kon = format!(
        r#"{{"url": "{ORIGIN}", "mandantId": "M", "workplaceId": "W", "clientSystemId": "C",
            "credentials": {{"type": "basic", "username": "u", "password": "p"}}}}"#
    );
    Dotkon::parse_with(kon.as_bytes(), |_| None).expect("the .kon file parses")
});

#[derive(Default)]
struct Sent(RefCell<Vec<String>>);

impl Transport for Sent {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        self.0.borrow_mut().push(request.url.to_owned());
        Err(TransportError {
            message: "no network".to_owned(),
            timed_out: false,
        })
    }
}

fn at_origin(url: &str) -> bool {
    url.to_ascii_lowercase()
        .strip_prefix(ORIGIN)
        .is_some_and(|p| p.is_empty() || p.starts_with(['/', '?', '#']))
}

fn check_nothing_leaves_the_origin(directory: &ServiceDirectory) {
    let sent = Sent::default();
    let connector = Connector::new(&KON, &sent, directory.clone(), Timeouts::RECOMMENDED);
    let _ = block_on(connector.cards().list(&[]));
    let _ = block_on(
        connector
            .pins()
            .status("card", ti_connector_client::PinType::Smc),
    );
    let _ = block_on(connector.signatures().job_number());
    for url in sent.0.borrow().iter() {
        assert!(at_origin(url), "{url} left the origin");
    }
}

fn supports(supported: &[&str], version: &str) -> bool {
    supported.iter().any(|s| {
        version == *s
            || version
                .strip_prefix(s)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn numeric(version: &str) -> Vec<u32> {
    version.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn offered<'a>(directory: &'a ServiceDirectory, service: &str) -> Vec<&'a ServiceVersion> {
    directory
        .services
        .iter()
        .filter(|s| s.name == service)
        .flat_map(|s| &s.versions)
        .collect()
}

fn check_binding(directory: &ServiceDirectory, service: &str, supported: &[&str]) {
    let offered = offered(directory, service);
    match directory.resolve(service, supported) {
        Ok(binding) => {
            assert_eq!(binding.service, service);
            assert!(supports(supported, &binding.version));
            assert!(offered.iter().any(|v| v.version == binding.version
                && v.endpoint_tls.as_ref().or(v.endpoint.as_ref()) == Some(&binding.endpoint)));
            let newest = offered
                .iter()
                .filter(|v| supports(supported, &v.version))
                .map(|v| numeric(&v.version))
                .max();
            assert_eq!(newest, Some(numeric(&binding.version)));
        }
        Err(DiscoveryError::NotAdvertised { .. }) => assert!(offered.is_empty()),
        Err(DiscoveryError::NoSupportedVersion { .. }) => {
            assert!(!offered.is_empty());
            assert!(!offered.iter().any(|v| supports(supported, &v.version)));
        }
        Err(DiscoveryError::NoEndpoint { .. }) => {
            assert!(offered.iter().any(|v| supports(supported, &v.version)));
        }
        Err(other) => panic!("no such refusal: {other}"),
    }
}

fuzz_target!(|xml: &[u8]| {
    let Ok(mut directory) = ServiceDirectory::parse(xml) else {
        return;
    };
    serde_json::to_string(&directory).expect("serializes");
    for (service, supported) in BINDINGS {
        check_binding(&directory, service, supported);
    }
    check_nothing_leaves_the_origin(&directory);
    directory.rewrite_endpoints(ORIGIN);
    for version in directory.services.iter().flat_map(|s| &s.versions) {
        for endpoint in [&version.endpoint_tls, &version.endpoint]
            .into_iter()
            .flatten()
        {
            assert!(at_origin(endpoint), "{endpoint} left the origin");
        }
    }
});
