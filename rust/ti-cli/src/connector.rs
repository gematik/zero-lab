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

//! Konnektor access for the `connector` commands: which `.kon` file (resolved as the Go
//! `ti` resolves it, sharing its files), the transport, the service directory through
//! the cache, and one diagnostic line per call.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use ti_client::connector::store::{self, Source};
use ti_client::connector::{UreqTransport, connect};
use ti_connector_client::{Request, Response, Timeouts, Transport, TransportError};

use crate::cli::{ConnectorArgs, GlobalArgs};
use crate::error::CliError;
use crate::output::{Output, diagnostic};

/// A Konnektor ready for calls.
pub type Session = ti_client::connector::Session<Logged<UreqTransport>>;

/// Where the configuration's name came from, as `-v` and the errors say it.
fn source_text(source: Source) -> &'static str {
    match source {
        Source::Explicit => "-c or TI_CONNECTOR_CONFIG",
        Source::Active => "the active selection",
        Source::Default => "the default name",
    }
}

/// Opens the selected Konnektor: reads its `.kon` file, sets up TLS from it, and loads
/// the service directory (through the cache unless `--no-cache`).
///
/// # Errors
///
/// [`CliError::ConnectorConfig`] or [`CliError::Connector`].
pub fn open(args: &ConnectorArgs, global: &GlobalArgs, out: &Output) -> Result<Session, CliError> {
    let (name, source) = store::selected(args.connector_config.as_deref());
    let path = store::resolve(&name).map_err(|e| match (source, e) {
        (Source::Active, ti_client::Error::ConnectorConfig(message)) => {
            CliError::ConnectorConfig(format!(
                "{message}; it is the active selection, change it with `{} connector use`",
                crate::BIN
            ))
        }
        (_, e) => e.into(),
    })?;
    out.verbose(
        1,
        format_args!(
            "connector {name} ({}): {}",
            source_text(source),
            path.display()
        ),
    );
    let dotkon = store::read(&path)?;
    if !dotkon.variables.is_empty() {
        out.verbose(
            1,
            format_args!(
                "expanded from the environment: {}",
                dotkon.variables.join(", ")
            ),
        );
    }
    let timeouts = Timeouts {
        short: args.connector_timeout,
        long: args.card_timeout,
    };
    out.verbose(
        1,
        format_args!(
            "timeouts: {} s per call, {} s with the card terminal",
            timeouts.short.as_secs(),
            timeouts.long.as_secs()
        ),
    );
    let transport = Logged::new(crate::http::client(&global.net, 0).connector(&dotkon)?, out);
    let cache = if args.no_cache {
        None
    } else {
        Some(crate::profile::open_cache(global)?)
    };
    let (connector, meta) = connect(&dotkon, transport, timeouts, cache)?;
    if let Some(meta) = meta {
        out.verbose(1, format_args!("service directory from {:?}", meta.source));
    }
    Ok(Session {
        connector,
        dotkon,
        name,
        comfort_user_id: args.comfort_user_id.clone(),
        state_dir: crate::profile::Profile::resolve(global)?.state_dir,
    })
}

/// The transport with a diagnostic per call: `-v` a line, `-vv` also the bodies, with
/// long base64 runs (documents, certificates) shortened. Never the `Authorization`
/// header, which only the inner transport sees.
pub struct Logged<T> {
    inner: T,
    verbosity: u8,
}

impl<T> Logged<T> {
    /// `inner` with the diagnostics `out`'s verbosity asks for.
    pub fn new(inner: T, out: &Output) -> Self {
        Logged {
            inner,
            verbosity: out.verbosity(),
        }
    }
}

impl<T: Transport> Transport for Logged<T> {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        let what = request.operation.map_or_else(
            || format!("GET {}", request.url),
            |op| {
                format!(
                    "{} {} {} → {}",
                    op.service, op.version, op.name, request.url
                )
            },
        );
        if self.verbosity >= 2 && !request.body.is_empty() {
            diagnostic(format_args!(
                "request {what}\n{}",
                shorten(&mask_user_id(request.body))
            ));
        }
        let start = Instant::now();
        let result = self.inner.send(request).await;
        let took = start.elapsed();
        if self.verbosity >= 1 {
            match &result {
                Ok(response) => diagnostic(format_args!(
                    "{what}: {} in {}",
                    response.status,
                    millis(took)
                )),
                Err(e) => diagnostic(format_args!("{what}: {e} after {}", millis(took))),
            }
        }
        if self.verbosity >= 2
            && let Ok(response) = &result
        {
            diagnostic(format_args!("response\n{}", shorten(&response.body)));
        }
        result
    }
}

fn millis(d: Duration) -> String {
    format!("{} ms", d.as_millis())
}

/// The body with the content of `UserId` elements masked: in a comfort signature
/// session it lets anyone with the same context sign without a PIN.
fn mask_user_id(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("UserId>") {
        let open = start + "UserId>".len();
        // `<…UserId>` opens the element and `</…UserId>` closes it; only an opening
        // tag is followed by the value.
        let closing = rest[..start]
            .rfind('<')
            .is_some_and(|lt| rest[lt + 1..].starts_with('/'));
        out.push_str(&rest[..open]);
        rest = &rest[open..];
        if !closing {
            let end = rest.find('<').unwrap_or(rest.len());
            if end > 0 {
                out.push_str("***");
            }
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out.into_bytes()
}

/// The body as text, each base64-looking run over 120 characters replaced by its
/// start and length: SOAP stays readable while documents do not flood the terminal.
fn shorten(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len().min(8192));
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() > 120 {
            out.push_str(&run[..40]);
            write!(out, "…[{} characters]", run.len()).expect("writing to a String cannot fail");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_are_masked() {
        let body =
            b"<c:Context><c:UserId>2b0a-secret</c:UserId><c:MandantId>M</c:MandantId></c:Context>";
        assert_eq!(
            String::from_utf8(mask_user_id(body)).unwrap(),
            "<c:Context><c:UserId>***</c:UserId><c:MandantId>M</c:MandantId></c:Context>"
        );
    }

    #[test]
    fn long_base64_runs_are_shortened() {
        let body = format!("<Data>{}</Data><Name>C.AUT</Name>", "QUJD".repeat(100));
        let short = shorten(body.as_bytes());
        assert!(short.starts_with("<Data>QUJDQUJD"), "{short}");
        assert!(
            short.contains("…[400 characters]</Data><Name>C.AUT</Name>"),
            "{short}"
        );
    }
}
