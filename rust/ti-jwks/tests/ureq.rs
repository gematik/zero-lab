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

//! The ureq transport against a loopback server: it sends the source's headers, hands back
//! a redirect and a 304 as answers, and stops reading at the limit.
#![cfg(feature = "ureq")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use futures_lite::future::block_on;
use ti_jwks::http::{Request, Transport};
use ti_jwks::ureq::UreqTransport;

/// Serves `answers` in turn, one connection each, and returns each request's head.
fn serve(answers: Vec<String>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        answers
            .into_iter()
            .map(|answer| {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    head.push_str(&line);
                }
                stream.write_all(answer.as_bytes()).unwrap();
                head
            })
            .collect()
    });
    (url, handle)
}

fn transport() -> UreqTransport {
    UreqTransport::new(UreqTransport::agent(ureq::Agent::config_builder()))
}

#[test]
fn the_ureq_transport_sends_the_headers_and_returns_every_status() {
    let body = r#"{"keys":[]}"#;
    let (url, server) = serve(vec![
        format!(
            "HTTP/1.1 200 OK\r\nCache-Control: max-age=600\r\nETag: \"v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
        "HTTP/1.1 302 Found\r\nLocation: http://elsewhere.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".into(),
    ]);
    let transport = transport();
    let request = Request {
        url: &url,
        headers: vec![("If-None-Match", "\"v0\"".into())],
        max_body: 1024,
    };
    let first = block_on(transport.get(&request)).unwrap();
    assert_eq!(first.status, 200);
    assert_eq!(first.body, body.as_bytes());
    assert_eq!(
        first.header("cache-control").as_deref(),
        Some("max-age=600")
    );
    assert_eq!(first.header("etag").as_deref(), Some("\"v1\""));
    assert_eq!(
        block_on(transport.get(&request)).unwrap().status,
        302,
        "not followed"
    );
    assert_eq!(block_on(transport.get(&request)).unwrap().status, 304);
    let heads = server.join().unwrap();
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("if-none-match: \"v0\""),
        "{}",
        heads[0]
    );
}

#[test]
fn the_ureq_transport_stops_reading_at_the_limit() {
    let body = "x".repeat(2048);
    let (url, server) = serve(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )]);
    let request = Request {
        url: &url,
        headers: Vec::new(),
        max_body: 1024,
    };
    let error = block_on(transport().get(&request)).unwrap_err();
    assert!(error.0.contains("longer than 1024 bytes"), "{error}");
    server.join().unwrap();
}
