//! The Konnektor's service directory (`connector.sds`): which services it offers, in
//! which versions, at which endpoints; and the choice of the version a binding speaks.

use serde::Serialize;
use sha2::{Digest, Sha256};
use ti_cache::{Cache, CacheEntry, CacheStore, Meta, OriginResponse, Source};
use ti_types::Clock;

use crate::error::{DiscoveryError, Error};
use crate::soap::{Method, Request, Response, Transport};

/// A parsed service directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceDirectory {
    /// What the Konnektor says it is.
    pub product: Product,
    /// Every service with its versions, in the order listed.
    pub services: Vec<Service>,
}

/// Product information of the Konnektor.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Product {
    /// E.g. `Konnektor`.
    pub product_type: String,
    /// E.g. `6.0.2`.
    pub product_type_version: String,
    /// Vendor identifier, e.g. `EHEXP`.
    pub vendor_id: String,
    /// Product code.
    pub product_code: String,
    /// Hardware version.
    pub hw_version: String,
    /// Firmware version.
    pub fw_version: String,
    /// Vendor name, when listed.
    pub vendor_name: Option<String>,
    /// Product name, when listed.
    pub product_name: Option<String>,
}

/// One service and the versions the Konnektor offers of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    /// E.g. `EventService`.
    pub name: String,
    /// The offered versions.
    pub versions: Vec<ServiceVersion>,
}

/// One offered version of a service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceVersion {
    /// E.g. `7.2.0`.
    pub version: String,
    /// The WSDL target namespace.
    pub target_namespace: String,
    /// The TLS endpoint.
    pub endpoint_tls: Option<String>,
    /// The plain endpoint.
    pub endpoint: Option<String>,
}

/// The version of a service a call goes to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    /// The service name.
    pub service: String,
    /// The full advertised version, e.g. `8.2.1`.
    pub version: String,
    /// Where to post: the TLS endpoint if listed, otherwise the plain one.
    pub endpoint: String,
}

impl ServiceDirectory {
    /// Parses `connector.sds`, matching elements by local name.
    ///
    /// # Errors
    ///
    /// [`Error::Decode`] if it is not a service directory.
    pub fn parse(xml: &[u8]) -> Result<Self, Error> {
        let text = core::str::from_utf8(xml).map_err(|e| Error::Decode(e.to_string()))?;
        let raw: xml::ConnectorServices = quick_xml::de::from_str(text)
            .map_err(|e| Error::Decode(format!("connector.sds: {e}")))?;
        let info = raw.product_information;
        let id = info.product_identification;
        let misc = info.product_miscellaneous.unwrap_or_default();
        Ok(ServiceDirectory {
            product: Product {
                product_type: info.product_type_information.product_type,
                product_type_version: info.product_type_information.product_type_version,
                vendor_id: id.product_vendor_id,
                product_code: id.product_code,
                hw_version: id.product_version.local.hw_version,
                fw_version: id.product_version.local.fw_version,
                vendor_name: misc.product_vendor_name,
                product_name: misc.product_name,
            },
            services: raw
                .service_information
                .service
                .into_iter()
                .map(|s| Service {
                    name: s.name,
                    versions: s
                        .versions
                        .version
                        .into_iter()
                        .map(|v| ServiceVersion {
                            version: v.version,
                            target_namespace: v.target_namespace,
                            endpoint_tls: v.endpoint_tls.map(|e| e.location),
                            endpoint: v.endpoint.map(|e| e.location),
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    /// Replaces scheme and host of every endpoint with those of `base`, keeping paths.
    pub fn rewrite_endpoints(&mut self, base: &str) {
        let Some((origin, _)) = split_origin(base) else {
            return;
        };
        let endpoints = self
            .services
            .iter_mut()
            .flat_map(|s| &mut s.versions)
            .flat_map(|v| [&mut v.endpoint_tls, &mut v.endpoint].into_iter().flatten());
        for endpoint in endpoints {
            if let Some((_, path)) = split_origin(endpoint) {
                *endpoint = format!("{origin}{path}");
            }
        }
    }

    /// The newest advertised version of `service` whose `major.minor` is in `supported`.
    /// The binding decides, not the Konnektor: each minor version has its own XML
    /// namespace, so a body for 8.1 posted to an 8.2 endpoint is answered with a fault.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError`] if the service is not listed, no listed version is supported,
    /// or the chosen version has no endpoint.
    pub fn resolve(&self, service: &str, supported: &[&str]) -> Result<Binding, DiscoveryError> {
        let offered: Vec<&ServiceVersion> = self
            .services
            .iter()
            .filter(|s| s.name == service)
            .flat_map(|s| &s.versions)
            .collect();
        if offered.is_empty() {
            return Err(DiscoveryError::NotAdvertised {
                service: service.to_owned(),
            });
        }
        let best = offered
            .iter()
            .filter(|v| supported.contains(&major_minor(&v.version)))
            .max_by_key(|v| numeric(&v.version))
            .ok_or_else(|| DiscoveryError::NoSupportedVersion {
                service: service.to_owned(),
                advertised: offered.iter().map(|v| v.version.clone()).collect(),
                supported: supported.iter().map(|&s| s.to_owned()).collect(),
            })?;
        let endpoint = best
            .endpoint_tls
            .clone()
            .or_else(|| best.endpoint.clone())
            .ok_or_else(|| DiscoveryError::NoEndpoint {
                service: service.to_owned(),
                version: best.version.clone(),
            })?;
        Ok(Binding {
            service: service.to_owned(),
            version: best.version.clone(),
            endpoint,
        })
    }

    /// Loads `connector.sds` below `base_url` from the Konnektor.
    ///
    /// # Errors
    ///
    /// [`Error::Transport`], [`Error::HttpStatus`] or [`Error::Decode`].
    pub async fn fetch(transport: &impl Transport, target: &Target<'_>) -> Result<Self, Error> {
        let response = get(transport, target, None, None).await?;
        match response.status {
            200 => Self::parse(&response.body),
            status => Err(Error::http_status(status, &response.body)),
        }
    }

    /// Like [`fetch`](Self::fetch), through `cache`: served from it while fresh,
    /// revalidated with `ETag`/`Last-Modified`, and served stale when the Konnektor is
    /// unreachable, as the cache's policy says. Keyed by URL under `ti-connector/v1/sds/`.
    /// The cache is as untrusted as the network: its bytes are parsed the same way.
    ///
    /// # Errors
    ///
    /// As [`fetch`](Self::fetch), plus [`Error::Cache`].
    pub async fn fetch_cached<S: CacheStore, C: Clock>(
        transport: &impl Transport,
        target: &Target<'_>,
        cache: &Cache<S, C>,
    ) -> Result<(Self, Meta), Error> {
        let url = sds_url(target.base_url);
        let key = format!(
            "ti-connector/v1/sds/{}",
            &hex(&Sha256::digest(url.as_bytes()))[..16]
        );
        let cached = cache
            .get(&key, async |validators| {
                let response =
                    get(transport, target, validators.etag, validators.last_modified).await?;
                let meta = Meta {
                    etag: response.etag.clone(),
                    last_modified: response.last_modified.clone(),
                    max_age: response.max_age,
                    ..Meta::new(cache.clock().now(), Source::Http)
                };
                match response.status {
                    200 => Ok(OriginResponse::Body(CacheEntry {
                        body: response.body,
                        meta,
                    })),
                    304 => Ok(OriginResponse::NotModified(meta)),
                    status => Err(Error::http_status(status, &response.body)),
                }
            })
            .await
            .map_err(Error::from_cache)?;
        Ok((Self::parse(&cached.body)?, cached.meta))
    }
}

/// Where the service directory is and how to ask for it.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// The `.kon` URL.
    pub base_url: &'a str,
    /// The `Authorization` header value, for basic credentials.
    pub authorization: Option<&'a str>,
    /// Timeout of the request.
    pub timeout: core::time::Duration,
}

async fn get(
    transport: &impl Transport,
    target: &Target<'_>,
    if_none_match: Option<&str>,
    if_modified_since: Option<&str>,
) -> Result<Response, Error> {
    let url = sds_url(target.base_url);
    transport
        .send(&Request {
            method: Method::Get,
            url: &url,
            soap_action: None,
            authorization: target.authorization,
            if_none_match,
            if_modified_since,
            body: &[],
            timeout: target.timeout,
            operation: None,
        })
        .await
        .map_err(Error::Transport)
}

/// `connector.sds` resolved against `base` as a relative reference: below a base
/// ending in `/`, next to its last segment otherwise.
pub fn sds_url(base: &str) -> String {
    let Some((origin, path)) = split_origin(base) else {
        return format!("{base}/connector.sds");
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let dir = path.rfind('/').map_or("/", |i| &path[..=i]);
    format!("{origin}{dir}connector.sds")
}

/// `("https://host:port", "/path?query")` of an http(s) URL with a host.
pub(crate) fn split_origin(url: &str) -> Option<(&str, &str)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if authority_len == 0 {
        return None;
    }
    let split = url.len() - rest.len() + authority_len;
    Some((&url[..split], &url[split..]))
}

/// `8.2` of `8.2.1`.
fn major_minor(version: &str) -> &str {
    let mut dots = version.match_indices('.');
    match (dots.next(), dots.next()) {
        (Some(_), Some((second, _))) => &version[..second],
        _ => version,
    }
}

/// Numeric components for ordering; non-numeric parts count as 0.
fn numeric(version: &str) -> Vec<u32> {
    version.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            write!(s, "{b:02x}").expect("writing to a String cannot fail");
            s
        })
}

/// The schema subset read, by local name.
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the schema's element names"
)]
mod xml {
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ConnectorServices {
        pub product_information: ProductInformation,
        pub service_information: ServiceInformation,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ProductInformation {
        pub product_type_information: ProductTypeInformation,
        pub product_identification: ProductIdentification,
        pub product_miscellaneous: Option<ProductMiscellaneous>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ProductTypeInformation {
        pub product_type: String,
        pub product_type_version: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ProductIdentification {
        #[serde(rename = "ProductVendorID")]
        pub product_vendor_id: String,
        pub product_code: String,
        pub product_version: ProductVersion,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ProductVersion {
        pub local: Local,
    }

    #[derive(Deserialize)]
    pub(super) struct Local {
        #[serde(rename = "HWVersion")]
        pub hw_version: String,
        #[serde(rename = "FWVersion")]
        pub fw_version: String,
    }

    #[derive(Default, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct ProductMiscellaneous {
        pub product_vendor_name: Option<String>,
        pub product_name: Option<String>,
    }

    #[derive(Deserialize)]
    pub(super) struct ServiceInformation {
        #[serde(rename = "Service", default)]
        pub service: Vec<Service>,
    }

    #[derive(Deserialize)]
    pub(super) struct Service {
        #[serde(rename = "@Name")]
        pub name: String,
        #[serde(rename = "Versions")]
        pub versions: Versions,
    }

    #[derive(Deserialize)]
    pub(super) struct Versions {
        #[serde(rename = "Version", default)]
        pub version: Vec<Version>,
    }

    #[derive(Deserialize)]
    pub(super) struct Version {
        #[serde(rename = "@Version")]
        pub version: String,
        #[serde(rename = "@TargetNamespace", default)]
        pub target_namespace: String,
        #[serde(rename = "EndpointTLS")]
        pub endpoint_tls: Option<Endpoint>,
        #[serde(rename = "Endpoint")]
        pub endpoint: Option<Endpoint>,
    }

    #[derive(Deserialize)]
    pub(super) struct Endpoint {
        #[serde(rename = "@Location")]
        pub location: String,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eHEX infinity Konnektor 6.0.2 (FW 2.0.1), captured by the Kotlin client's tests.
    const EHEX: &[u8] = include_bytes!("../tests/fixtures/ehex-connector.sds");

    #[test]
    fn ehex_fixture_is_pinned() {
        assert_eq!(
            hex(&Sha256::digest(EHEX)),
            include_str!("../tests/fixtures/ehex-connector.sds.sha256").trim()
        );
    }

    #[test]
    fn parses_the_ehex_directory() {
        let sds = ServiceDirectory::parse(EHEX).unwrap();
        assert_eq!(
            (
                &*sds.product.vendor_id,
                &*sds.product.product_type_version,
                sds.product.product_name.as_deref()
            ),
            ("EHEXP", "6.0.2", Some("infinity konnektor"))
        );
        let names: Vec<&str> = sds.services.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"EventService") && names.contains(&"CardService"));
    }

    #[test]
    fn resolves_the_newest_supported_version() {
        let sds = ServiceDirectory::parse(EHEX).unwrap();
        let card = sds.resolve("CardService", &["8.1"]).unwrap();
        assert_eq!(
            card.version, "8.1.2",
            "8.2.1 is advertised but not asked for"
        );
        assert!(card.endpoint.starts_with("https://"));
        assert_eq!(
            sds.resolve("CardService", &["8.2"]).unwrap().version,
            "8.2.1"
        );
        assert_eq!(
            sds.resolve("SignatureService", &["7.4", "7.5"])
                .unwrap()
                .version,
            "7.5.5"
        );
        assert_eq!(
            sds.resolve("SignatureService", &["7.4"]).unwrap().version,
            "7.4.2"
        );
        assert_eq!(
            sds.resolve("CardService", &["9.0"]),
            Err(DiscoveryError::NoSupportedVersion {
                service: "CardService".into(),
                advertised: vec![
                    "8.1.2".into(),
                    "8.1.1".into(),
                    "8.1.0".into(),
                    "8.2.1".into()
                ],
                supported: vec!["9.0".into()],
            })
        );
        assert_eq!(
            sds.resolve("PoppService", &["1.0"]),
            Err(DiscoveryError::NotAdvertised {
                service: "PoppService".into()
            })
        );
    }

    #[test]
    fn rewrites_scheme_and_host_only() {
        let mut sds = ServiceDirectory::parse(EHEX).unwrap();
        sds.rewrite_endpoints("https://localhost:8443/base/");
        let event = sds.resolve("EventService", &["7.2"]).unwrap();
        assert_eq!(event.endpoint, "https://localhost:8443/ws/EventService");
    }

    #[test]
    fn sds_url_resolves_like_a_relative_reference() {
        for (base, sds) in [
            ("https://k:443", "https://k:443/connector.sds"),
            ("https://k/", "https://k/connector.sds"),
            ("https://k/konnektor/", "https://k/konnektor/connector.sds"),
            ("https://k/konnektor", "https://k/connector.sds"),
            ("http://k/a/b?x=1", "http://k/a/connector.sds"),
        ] {
            assert_eq!(sds_url(base), sds, "{base}");
        }
        assert_eq!(split_origin("https:///x"), None);
        assert_eq!(split_origin("ftp://k"), None);
    }
}
