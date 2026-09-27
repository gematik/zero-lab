//! A session recorded with a real Konnektor (eHEX infinity 6.0.2, FW 2.0.1, TEST-ONLY
//! SMC-B; `TI_TEST_KON_RECORD_DIR` in `tests/e2e.rs`), replayed offline: every request
//! must equal the recorded one byte for byte, and every recorded answer must decode to
//! what the live run saw.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::Path;

use futures_lite::future::block_on;
use sha2::{Digest, Sha256};
use ti_connector_client::types::{CardType, CertRef, Crypt, PinState};
use ti_connector_client::{
    Connector, Dotkon, Request, Response, SignatureFormat, SignatureType, Timeouts, ToSign,
    Transport, TransportError,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/recorded/ehex-6.0.2"
);

/// One recorded exchange.
struct Exchange {
    name: String,
    request: Option<Vec<u8>>,
    status: u16,
    response: Vec<u8>,
}

/// Answers from the recording in order, and checks each request against it.
struct Replay(RefCell<VecDeque<Exchange>>);

impl Replay {
    fn load(dir: &Path) -> Self {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.contains(".response-"))
            .collect();
        names.sort();
        let exchanges = names
            .into_iter()
            .map(|file| {
                let (stem, status) = file.split_once(".response-").unwrap();
                let name = stem.split_once('-').unwrap().1.to_owned();
                Exchange {
                    request: std::fs::read(dir.join(format!("{stem}.request.xml"))).ok(),
                    status: status.trim_end_matches(".xml").parse().unwrap(),
                    response: std::fs::read(dir.join(&file)).unwrap(),
                    name,
                }
            })
            .collect();
        Replay(RefCell::new(exchanges))
    }
}

impl Transport for Replay {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        let next = self
            .0
            .borrow_mut()
            .pop_front()
            .expect("a recorded exchange left");
        let name = request.operation.map_or("connector-sds", |op| op.name);
        assert_eq!(name, next.name, "the recorded order of calls");
        if let Some(recorded) = &next.request {
            assert_eq!(
                String::from_utf8_lossy(request.body),
                String::from_utf8_lossy(recorded),
                "{name}: the request differs from what the Konnektor accepted"
            );
        }
        Ok(Response {
            status: next.status,
            body: next.response,
            ..Response::default()
        })
    }
}

#[test]
fn the_recorded_ehex_session_replays() {
    let kon = r#"{"url": "https://10.29.128.70", "mandantId": "praxis", "workplaceId": "server",
        "clientSystemId": "pvs", "userId": "0987654321",
        "credentials": {"type": "basic", "username": "u", "password": "p"}}"#;
    let dotkon = Dotkon::parse_with(kon.as_bytes(), |_| None).unwrap();
    let replay = Replay::load(Path::new(DIR));
    let connector = block_on(Connector::connect(&dotkon, &replay, Timeouts::RECOMMENDED)).unwrap();

    let cards = block_on(connector.cards().list(&[CardType::SmcB, CardType::Hba])).unwrap();
    assert_eq!(
        (
            cards.len(),
            &*cards[0].card_handle,
            cards[0].iccsn.as_deref()
        ),
        (1, "SMC-B-2", Some("80276883110000162094"))
    );
    let handle = &cards[0].card_handle;
    let status = block_on(
        connector
            .pins()
            .status(handle, ti_connector_client::PinType::Smc),
    )
    .unwrap();
    assert_eq!(status.pin_status, Some(PinState::Verified));

    let aut = block_on(
        connector
            .certificates()
            .read(handle, Crypt::Ecc, &[CertRef::CAut]),
    )
    .unwrap();
    let aut = &aut[0].certificate;
    let message = b"ti-connector-client e2e";
    let raw = block_on(connector.auth().external_authenticate(
        handle,
        &Sha256::digest(message),
        SignatureType::Ecdsa,
    ))
    .unwrap();
    assert_eq!(raw.len(), 64, "raw R‖S on brainpoolP256r1");
    let algorithm = ti_pki::algorithms::brainpool::ECDSA_BP256R1_SHA256;
    algorithm
        .verify_signature(aut.public_key(), message, &der_signature(&raw))
        .expect("the recorded signature verifies against C.AUT");

    let signed = block_on(connector.signatures().sign(
        handle,
        SignatureFormat::Cades,
        Some(Crypt::Ecc),
        &[ToSign {
            content: message.as_slice(),
            mime_type: "text/plain",
            short_text: None,
        }],
    ))
    .unwrap();
    let cms = signed[0].signature.clone().expect("a CMS signature");
    assert_eq!(signed[0].signed_document, None, "detached");
    let verdict = block_on(connector.signatures().verify(
        SignatureFormat::Cades,
        message,
        "text/plain",
        Some(&cms),
    ))
    .unwrap();
    assert_eq!(verdict.verification_result.high_level_result, "VALID");

    let enc = block_on(
        connector
            .certificates()
            .read(handle, Crypt::Ecc, &[CertRef::CEnc]),
    )
    .unwrap();
    let encrypted = block_on(connector.encryption().encrypt(
        &[enc[0].certificate.der()],
        message,
        "text/plain",
    ))
    .unwrap();
    let decrypted = block_on(connector.encryption().decrypt(
        handle,
        Some(Crypt::Ecc),
        &encrypted,
        "text/plain",
    ))
    .unwrap();
    assert_eq!(decrypted, message);

    assert!(
        block_on(connector.cards().list(&[CardType::Hba]))
            .unwrap()
            .is_empty()
    );
    assert!(
        replay.0.borrow().is_empty(),
        "every recorded exchange was used"
    );
}

/// DER `ECDSA-Sig-Value` of a raw R‖S signature.
fn der_signature(raw: &[u8]) -> Vec<u8> {
    let integer = |n: &[u8]| {
        let n = &n[n.iter().take_while(|&&b| b == 0).count()..];
        let mut value = if n.first().is_some_and(|&b| b >= 0x80) {
            vec![0]
        } else {
            vec![]
        };
        value.extend(n);
        let mut out = vec![0x02, u8::try_from(value.len()).unwrap()];
        out.extend(value);
        out
    };
    let (r, s) = raw.split_at(raw.len() / 2);
    let body = [integer(r), integer(s)].concat();
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}
