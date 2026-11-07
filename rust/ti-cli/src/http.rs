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
//! [`NetArgs`], with `-v` lines on stderr: one per download, OCSP request and call to the
//! Konnektor, the IDP-Dienst or the FHIR-Directory; `-vv` adds the bodies.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use ti_client::Client;
use ti_client::http::Http;
use ti_client::watch::{Exchange, Request, Service};

use crate::error::CliError;
use crate::net::NetArgs;
use crate::output::diagnostic;

/// The client of `net`, telling `-v` about each request.
pub fn client(net: &NetArgs, verbose: u8) -> Client {
    let client = Client::new(net.net());
    if verbose >= 1 {
        client
            .observed(Arc::new(|message| diagnostic(message)))
            .watched(Arc::new(move |exchange| show(exchange, verbose)))
    } else {
        client
    }
}

/// The transport for downloads and OCSP. `-k` skips the TLS check for downloads only: the
/// TSL and roots.json are verified by their content, and the report says so.
pub fn transport(net: &NetArgs, verbose: u8) -> Result<Http, CliError> {
    Ok(client(net, verbose).downloads()?)
}

/// The lines of one exchange: for the Konnektor a line per call with its time, and at
/// `-vv` both bodies, long base64 runs (documents, certificates) shortened; for the
/// IDP-Dienst and the FHIR-Directory a line per request, and at `-vv` the body of an
/// answer that is neither a success nor a redirect.
fn show(exchange: &Exchange<'_>, verbose: u8) {
    match *exchange {
        Exchange::Sending(request) => {
            if request.service == Service::Konnektor && verbose >= 2 && request.has_body() {
                diagnostic(format_args!(
                    "request {}\n{}",
                    konnektor_call(request),
                    shorten(&request.body())
                ));
            }
        }
        Exchange::Done {
            request,
            answer,
            took,
        } if request.service == Service::Konnektor => {
            let what = konnektor_call(request);
            match answer {
                Ok(answer) => {
                    diagnostic(format_args!(
                        "{what}: {} in {}",
                        answer.status,
                        millis(took)
                    ));
                    if verbose >= 2 {
                        diagnostic(format_args!("response\n{}", shorten(answer.body)));
                    }
                }
                Err(e) => diagnostic(format_args!("{what}: {e} after {}", millis(took))),
            }
        }
        Exchange::Done {
            request, answer, ..
        } => match answer {
            Ok(answer) => {
                diagnostic(format_args!(
                    "{} {} → {} ({} bytes)",
                    request.method,
                    request.url,
                    answer.status,
                    answer.body.len()
                ));
                if verbose >= 2 && !(200..400).contains(&answer.status) && !answer.body.is_empty() {
                    diagnostic(String::from_utf8_lossy(answer.body).trim_end());
                }
            }
            Err(e) => diagnostic(format_args!("{} {} → {e}", request.method, request.url)),
        },
    }
}

/// `SignatureService 7.5 SignDocument → URL` for a SOAP call, `GET URL` for the service
/// directory.
fn konnektor_call(request: &Request<'_>) -> String {
    request.operation.map_or_else(
        || format!("GET {}", request.url),
        |op| {
            format!(
                "{} {} {} → {}",
                op.service, op.version, op.name, request.url
            )
        },
    )
}

fn millis(d: Duration) -> String {
    format!("{} ms", d.as_millis())
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
