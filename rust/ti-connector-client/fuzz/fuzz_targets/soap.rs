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

//! Any bytes as a Konnektor's answer, through the public calls over a transport that
//! returns them: no call panics or fails with anything but a decode error, a fault or
//! the HTTP status; only a 200 can be a success; and a body that holds a fault is that
//! fault in every call and at any status, never a success.
#![no_main]

use std::sync::LazyLock;

use futures_lite::future::block_on;
use libfuzzer_sys::fuzz_target;
use ti_connector_client::types::{CardType, CertRef, Crypt};
use ti_connector_client::{
    ComfortUserId, Connector, Dotkon, Error, PinType, Request, Response, ServiceDirectory,
    SignatureFormat, SignatureType, Timeouts, ToSign, Transport, TransportError,
};

static KON: LazyLock<Dotkon> = LazyLock::new(|| {
    let kon = br#"{"url": "https://konnektor.test", "rewriteServiceEndpoints": true,
        "mandantId": "M", "workplaceId": "W",
        "clientSystemId": "C", "credentials": {"type": "basic", "username": "u", "password": "p"}}"#;
    Dotkon::parse_with(kon, |_| None).expect("the .kon file parses")
});
static DIRECTORY: LazyLock<ServiceDirectory> = LazyLock::new(|| {
    ServiceDirectory::parse(include_bytes!("../../tests/fixtures/ehex-connector.sds"))
        .expect("the fixture parses")
});

struct Answer<'a> {
    status: u16,
    body: &'a [u8],
}

impl Transport for Answer<'_> {
    async fn send(&self, _: &Request<'_>) -> Result<Response, TransportError> {
        Ok(Response {
            status: self.status,
            body: self.body.to_vec(),
            ..Response::default()
        })
    }
}

fn connector(status: u16, body: &[u8]) -> Connector<Answer<'_>> {
    Connector::new(
        &KON,
        Answer { status, body },
        DIRECTORY.clone(),
        Timeouts::RECOMMENDED,
    )
}

/// What the body is, at a status that is no success: a fault, or nothing a call may use.
fn holds_a_fault(body: &[u8]) -> bool {
    let connector = connector(500, body);
    match block_on(connector.pins().status("card", PinType::Ch)) {
        Ok(_) => panic!("a success at status 500"),
        Err(Error::Fault(fault)) => {
            let _ = (fault.to_string(), fault.hint());
            true
        }
        Err(Error::HttpStatus { status, .. }) => {
            assert_eq!(status, 500);
            assert!(core::str::from_utf8(body).is_ok());
            false
        }
        Err(Error::Decode(_)) => {
            assert!(core::str::from_utf8(body).is_err());
            false
        }
        Err(other) => panic!("no such failure: {other}"),
    }
}

fn check<T>(result: Result<T, Error>, faulted: bool, body: &[u8]) {
    let text = core::str::from_utf8(body).is_ok();
    match result {
        Ok(_) => assert!(text && !faulted, "a success from a fault or from non-text"),
        Err(Error::Fault(fault)) => {
            assert!(text);
            let _ = (fault.to_string(), fault.hint());
        }
        Err(Error::Decode(_)) => assert!(!faulted, "a fault read as garbage"),
        Err(other) => panic!("no such failure: {other}"),
    }
}

fuzz_target!(|body: &[u8]| {
    let faulted = holds_a_fault(body);
    let connector = connector(200, body);
    let user = ComfortUserId::generate(|bytes| bytes.fill(7));
    let document = ToSign {
        content: b"TEST-ONLY",
        mime_type: "text/plain",
        short_text: None,
    };
    let signatures = connector.signatures();
    let certificates = connector.certificates();
    let encryption = connector.encryption();
    let pins = connector.pins();
    block_on(async {
        check(connector.status().await, faulted, body);
        check(connector.cards().list(&[]).await, faulted, body);
        check(connector.cards().get("card").await, faulted, body);
        check(
            certificates
                .read("card", Crypt::Ecc, &[CertRef::CAut])
                .await,
            faulted,
            body,
        );
        check(
            certificates.read_all("card", CardType::SmcB).await,
            faulted,
            body,
        );
        check(
            certificates.expiration(None, Crypt::Ecc).await,
            faulted,
            body,
        );
        check(certificates.verify(b"der", None).await, faulted, body);
        check(pins.status("card", PinType::Smc).await, faulted, body);
        check(pins.verify("card", PinType::Smc).await, faulted, body);
        check(pins.change("card", PinType::Smc).await, faulted, body);
        check(
            connector
                .auth()
                .external_authenticate("card", &[0; 32], SignatureType::Ecdsa)
                .await,
            faulted,
            body,
        );
        check(signatures.job_number().await, faulted, body);
        check(
            signatures
                .sign_in_job("job", "card", SignatureFormat::Cades, None, &[document])
                .await,
            faulted,
            body,
        );
        check(
            signatures
                .verify(SignatureFormat::Cades, b"doc", "text/plain", Some(b"sig"))
                .await,
            faulted,
            body,
        );
        check(signatures.stop("job").await, faulted, body);
        check(
            signatures.activate_comfort("card", &user).await,
            faulted,
            body,
        );
        check(
            signatures.deactivate_comfort(&["card"]).await,
            faulted,
            body,
        );
        check(signatures.mode("card", &user).await, faulted, body);
        check(
            encryption.encrypt(&[b"der"], b"doc", "text/plain").await,
            faulted,
            body,
        );
        check(
            encryption.decrypt("card", None, b"cms", "text/plain").await,
            faulted,
            body,
        );
    });
});
