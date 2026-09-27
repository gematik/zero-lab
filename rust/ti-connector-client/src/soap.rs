//! The one generic SOAP call behind every facade method, and the [`Transport`] it
//! goes through. The caller's transport owns TLS (including client certificates),
//! proxies and connection handling; this crate has no HTTP code of its own.

use core::fmt;
use core::time::Duration;

use serde::Deserialize;

use crate::api::soap::{Envelope, SoapOperation, SoapRequest, SoapResponse, Timeout};
use crate::connector::Connector;
use crate::error::{Error, Fault, TraceEntry};

/// HTTP method of a [`Request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// The service directory.
    Get,
    /// A SOAP call.
    Post,
}

/// An HTTP request to the Konnektor.
///
/// A SOAP call ([`soap_action`](Self::soap_action) set) is sent with
/// `Content-Type: text/xml; charset=utf-8` and the `SOAPAction` header.
#[derive(Clone)]
pub struct Request<'a> {
    /// GET or POST.
    pub method: Method,
    /// Absolute URL.
    pub url: &'a str,
    /// The `SOAPAction` header value of a SOAP call.
    pub soap_action: Option<&'a str>,
    /// The `Authorization` header value, for basic credentials. Never log it.
    pub authorization: Option<&'a str>,
    /// `If-None-Match` for a conditional GET.
    pub if_none_match: Option<&'a str>,
    /// `If-Modified-Since` for a conditional GET.
    pub if_modified_since: Option<&'a str>,
    /// The body; empty for GET.
    pub body: &'a [u8],
    /// The whole exchange must finish within this; the transport enforces it.
    pub timeout: Duration,
    /// The operation of a SOAP call, for diagnostics.
    pub operation: Option<&'a SoapOperation>,
}

impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("soap_action", &self.soap_action)
            .field("authorization", &self.authorization.map(|_| "<redacted>"))
            .field("body_len", &self.body.len())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// The Konnektor's answer, whatever the status.
#[derive(Clone, Debug, Default)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
    /// `ETag`, if sent.
    pub etag: Option<String>,
    /// `Last-Modified`, if sent.
    pub last_modified: Option<String>,
    /// `Cache-Control: max-age`, if sent.
    pub max_age: Option<Duration>,
}

/// A request that produced no HTTP response.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    /// What went wrong, including causes (refused, TLS, name resolution).
    pub message: String,
    /// The request ran into its timeout.
    pub timed_out: bool,
}

/// Sends requests to the Konnektor. Implemented by the caller over its HTTP client, or
/// by the `ureq` feature's adapter.
#[allow(
    async_fn_in_trait,
    reason = "no Send bound on purpose: implementable on wasm32"
)]
pub trait Transport {
    /// Sends `request` and returns the response, whatever its status.
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError>;
}

impl<T: Transport + ?Sized> Transport for &T {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        (**self).send(request).await
    }
}

/// How long operations may take: `short` for lookups, `long` for anything that waits
/// for the card terminal (PIN entry) or does card cryptography.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Lookups and the service directory.
    pub short: Duration,
    /// PIN entry and card cryptography.
    pub long: Duration,
}

impl Timeouts {
    /// 10 seconds and 5 minutes: long enough for a user to find the card terminal.
    pub const RECOMMENDED: Timeouts = Timeouts {
        short: Duration::from_secs(10),
        long: Duration::from_mins(5),
    };

    /// The timeout of `class`.
    pub fn of(self, class: Timeout) -> Duration {
        match class {
            Timeout::Short => self.short,
            Timeout::Long => self.long,
        }
    }
}

impl<T: Transport> Connector<T> {
    /// Calls `R`'s operation at the newest advertised version of its service that `R`
    /// was generated for.
    pub(crate) async fn call<R: SoapRequest>(
        &self,
        request: impl Into<R>,
    ) -> Result<<R::Response as SoapResponse>::Success, Error> {
        let operation = &R::OPERATION;
        let binding = self
            .directory()
            .resolve(operation.service, &[operation.version])?;
        let xml = Envelope::new(request.into())
            .to_xml()
            .map_err(|e| Error::Decode(format!("encoding {}: {e}", operation.name)))?;
        let response = self
            .transport()
            .send(&Request {
                method: Method::Post,
                url: &binding.endpoint,
                soap_action: Some(operation.soap_action),
                authorization: self.authorization(),
                if_none_match: None,
                if_modified_since: None,
                body: xml.as_bytes(),
                timeout: self.timeouts().of(operation.timeout),
                operation: Some(operation),
            })
            .await
            .map_err(Error::Transport)?;
        decode::<R::Response>(operation, &response)
    }
}

/// The result of a SOAP response: the typed success, or a [`Fault`] read leniently,
/// so a Konnektor that omits a field of the gematik error trace still yields the fault.
fn decode<R: SoapResponse + serde::de::DeserializeOwned>(
    operation: &SoapOperation,
    response: &Response,
) -> Result<R::Success, Error> {
    let text = core::str::from_utf8(&response.body)
        .map_err(|e| Error::Decode(format!("{}: response is not UTF-8: {e}", operation.name)))?;
    if let Some(fault) = fault(text) {
        return Err(Error::Fault(fault));
    }
    if response.status != 200 {
        return Err(Error::http_status(response.status, &response.body));
    }
    match Envelope::<R>::from_xml(text) {
        Ok(envelope) => envelope.into_content().into_result().map_err(|fault| {
            Error::Fault(Fault {
                code: fault.faultcode,
                message: fault.faultstring,
                trace: Vec::new(),
            })
        }),
        Err(e) => Err(Error::Decode(format!("{}: {e}", operation.name))),
    }
}

/// The fault in `xml`, if it is one.
fn fault(xml: &str) -> Option<Fault> {
    let envelope: lenient::Envelope = quick_xml::de::from_str(xml).ok()?;
    let fault = envelope.body.fault?;
    let trace = fault
        .detail
        .and_then(|d| d.error)
        .map(|e| e.trace)
        .unwrap_or_default()
        .into_iter()
        .map(|t| TraceEntry {
            code: t.code,
            error_text: t.error_text,
            error_type: t.error_type,
            severity: t.severity,
            event_id: t.event_id,
            comp_type: t.comp_type,
            detail: t.detail.map(|d| d.text).filter(|d| !d.trim().is_empty()),
        })
        .collect();
    Some(Fault {
        code: fault.faultcode,
        message: fault.faultstring,
        trace,
    })
}

/// SOAP 1.1 faults with the gematik error trace (`tel/error/v2.0`) in `detail`, every
/// field optional.
mod lenient {
    use super::Deserialize;

    #[derive(Deserialize)]
    pub(super) struct Envelope {
        #[serde(rename = "Body")]
        pub body: Body,
    }

    #[derive(Deserialize)]
    pub(super) struct Body {
        #[serde(rename = "Fault")]
        pub fault: Option<Fault>,
    }

    #[derive(Deserialize)]
    pub(super) struct Fault {
        #[serde(default)]
        pub faultcode: String,
        #[serde(default)]
        pub faultstring: String,
        pub detail: Option<Detail>,
    }

    #[derive(Deserialize)]
    pub(super) struct Detail {
        #[serde(rename = "Error")]
        pub error: Option<Error>,
    }

    #[derive(Deserialize)]
    pub(super) struct Error {
        #[serde(rename = "Trace", default)]
        pub trace: Vec<Trace>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub(super) struct Trace {
        pub code: Option<i64>,
        pub error_text: Option<String>,
        pub error_type: Option<String>,
        pub severity: Option<String>,
        #[serde(rename = "EventID")]
        pub event_id: Option<String>,
        pub comp_type: Option<String>,
        pub detail: Option<TraceDetail>,
    }

    #[derive(Deserialize)]
    pub(super) struct TraceDetail {
        #[serde(rename = "$text", default)]
        pub text: String,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_gematik_trace_from_a_lowercase_detail() {
        let xml = r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body><soap:Fault>
            <faultcode>soap:Server</faultcode><faultstring>Karte nicht gesteckt</faultstring>
            <detail><e:Error xmlns:e="http://ws.gematik.de/tel/error/v2.0">
              <e:MessageID>m</e:MessageID>
              <e:Trace><e:Code>4008</e:Code><e:ErrorText>Karte nicht als gesteckt identifiziert</e:ErrorText>
                <e:ErrorType>Technical</e:ErrorType><e:Severity>Error</e:Severity>
                <e:Detail Encoding="text">slot 3</e:Detail></e:Trace>
            </e:Error></detail>
          </soap:Fault></soap:Body></soap:Envelope>"#;
        let fault = fault(xml).unwrap();
        assert_eq!(
            (&*fault.code, &*fault.message),
            ("soap:Server", "Karte nicht gesteckt")
        );
        assert_eq!(fault.trace.len(), 1);
        assert_eq!(fault.trace[0].code, Some(4008));
        assert_eq!(fault.trace[0].detail.as_deref(), Some("slot 3"));
        assert_eq!(
            fault.to_string(),
            "SOAP fault soap:Server: Karte nicht gesteckt (4008 Karte nicht als gesteckt identifiziert: slot 3)"
        );
    }

    #[test]
    fn a_response_is_no_fault() {
        assert!(fault("<Envelope><Body><GetCardsResponse/></Body></Envelope>").is_none());
        assert!(fault("not xml").is_none());
    }
}
