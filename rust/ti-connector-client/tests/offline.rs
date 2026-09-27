//! The client against a scripted transport, with the Go client's fixtures
//! (`go/kon/cards_test.go`) and a captured eHEX service directory.

mod support;

use std::cell::Cell;
use std::time::Duration;

use futures_lite::future::block_on;
use ti_cache::{Cache, CachePolicy, MemoryCacheStore, Source};
use ti_connector_client::types::CardType;
use ti_connector_client::{
    Connector, DiscoveryError, Dotkon, Error, Method, Response, ServiceDirectory, Timeouts,
    TransportError,
};
use ti_types::{Clock, Timestamp};

use support::{Scripted, ok};

const GO_SDS: &str = include_str!("fixtures/go-connector.sds");
const GO_CARDS: &str = include_str!("fixtures/go-get-cards.xml");
const GO_FAULT: &str = include_str!("fixtures/go-get-cards-fault.xml");
const EHEX_SDS: &[u8] = include_bytes!("fixtures/ehex-connector.sds");

const KON: &str = r#"{
    "url": "https://konnektor.test",
    "mandantId": "M1", "workplaceId": "W1", "clientSystemId": "C1",
    "credentials": {"type": "basic", "username": "u", "password": "p"}
}"#;

fn go_sds() -> String {
    GO_SDS.replace("%%ENDPOINT%%", "https://konnektor.test")
}

fn dotkon() -> Dotkon {
    Dotkon::parse_with(KON.as_bytes(), |_| None).unwrap()
}

const TIMEOUTS: Timeouts = Timeouts {
    short: Duration::from_secs(3),
    long: Duration::from_secs(99),
};

#[test]
fn lists_cards_like_the_go_client() {
    let transport = Scripted::new([ok(200, &go_sds()), ok(200, GO_CARDS)]);
    let connector = block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap();
    let cards = block_on(connector.cards().list(&[])).unwrap();

    assert_eq!(cards.len(), 2);
    assert_eq!(
        (
            &*cards[0].card_handle,
            cards[0].card_type,
            cards[0].iccsn.as_deref(),
            &*cards[0].ct_id,
            cards[0].card_holder_name.as_deref()
        ),
        (
            "card-smcb-1",
            CardType::SmcB,
            Some("80276123456789010001"),
            "CT_ID_1",
            Some("Test Practice")
        )
    );
    assert_eq!(
        (&*cards[1].card_handle, cards[1].card_type),
        ("card-hba-1", CardType::Hba)
    );

    let seen = transport.seen.borrow();
    assert_eq!(
        (seen[0].method, &*seen[0].url, seen[0].timeout),
        (
            Method::Get,
            "https://konnektor.test/connector.sds",
            TIMEOUTS.short
        )
    );
    let call = &seen[1];
    assert_eq!(
        (call.method, &*call.url),
        (Method::Post, "https://konnektor.test/ws/EventService")
    );
    assert_eq!(
        call.soap_action.as_deref(),
        Some("http://ws.gematik.de/conn/EventService/v7.2#GetCards")
    );
    assert_eq!(
        call.timeout, TIMEOUTS.short,
        "GetCards is a short operation"
    );
    assert_eq!(call.authorization.as_deref(), Some("Basic dTpw"));
    for part in [
        "<SOAP-ENV:Envelope",
        "<eventservice72:GetCards>",
        "<connectorcommon50:MandantId>M1</connectorcommon50:MandantId>",
        "<connectorcommon50:WorkplaceId>W1</connectorcommon50:WorkplaceId>",
        "<connectorcommon50:ClientSystemId>C1</connectorcommon50:ClientSystemId>",
    ] {
        assert!(call.body.contains(part), "{part} in {}", call.body);
    }
    assert!(!call.body.contains("CardType"), "no filter: all cards");
}

#[test]
fn card_types_are_queried_one_by_one_and_deduplicated() {
    let transport = Scripted::new([ok(200, &go_sds()), ok(200, GO_CARDS), ok(200, GO_CARDS)]);
    let connector = block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap();
    let cards = block_on(connector.cards().list(&[CardType::SmcB, CardType::Hba])).unwrap();
    assert_eq!(cards.len(), 2);
    let seen = transport.seen.borrow();
    assert!(
        seen[1]
            .body
            .contains(">SMC-B</cardservicecommon20:CardType>")
    );
    assert!(seen[2].body.contains(">HBA</cardservicecommon20:CardType>"));
}

#[test]
fn a_fault_is_an_error_whatever_the_status() {
    for status in [200, 500] {
        let transport = Scripted::new([ok(200, &go_sds()), ok(status, GO_FAULT)]);
        let connector = block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap();
        let Err(Error::Fault(fault)) = block_on(connector.cards().list(&[])) else {
            panic!("expected a fault for HTTP {status}");
        };
        assert_eq!(
            (&*fault.code, &*fault.message),
            ("soap:Server", "internal error")
        );
    }
}

#[test]
fn other_failures() {
    let transport = Scripted::new([ok(200, &go_sds()), ok(401, "denied")]);
    let connector = block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap();
    assert_eq!(
        block_on(connector.cards().list(&[])),
        Err(Error::HttpStatus {
            status: 401,
            body: "denied".into()
        })
    );

    let refused = TransportError {
        message: "connection refused".into(),
        timed_out: false,
    };
    let transport = Scripted::failing(refused.clone());
    assert_eq!(
        block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap_err(),
        Error::Transport(refused)
    );

    let transport = Scripted::new([ok(200, "<nothing/>")]);
    assert!(matches!(
        block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)),
        Err(Error::Decode(_))
    ));
}

#[test]
fn a_service_the_konnektor_lacks_is_never_called() {
    let sds = go_sds().replace("EventService", "CardService");
    let transport = Scripted::new([ok(200, &sds)]);
    let connector = block_on(Connector::connect(&dotkon(), &transport, TIMEOUTS)).unwrap();
    assert_eq!(
        block_on(connector.cards().list(&[])),
        Err(Error::Discovery(DiscoveryError::NotAdvertised {
            service: "EventService".into()
        }))
    );
    assert_eq!(transport.seen.borrow().len(), 1);
}

#[test]
fn rewrites_endpoints_when_asked() {
    let kon = KON.replace(
        "\"url\": \"https://konnektor.test\"",
        "\"url\": \"https://127.0.0.1:8443\", \"rewriteServiceEndpoints\": true",
    );
    let dotkon = Dotkon::parse_with(kon.as_bytes(), |_| None).unwrap();
    let directory = ServiceDirectory::parse(EHEX_SDS).unwrap();
    let transport = Scripted::new([]);
    let connector = Connector::new(&dotkon, &transport, directory, TIMEOUTS);
    assert_eq!(
        connector
            .directory()
            .resolve("EventService", &["7.2"])
            .unwrap()
            .endpoint,
        "https://127.0.0.1:8443/ws/EventService"
    );
}

struct TestClock(Cell<Timestamp>);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        self.0.get()
    }
}

#[test]
fn the_directory_is_cached_and_revalidated() {
    let store = MemoryCacheStore::new();
    let cache = Cache::new(
        &store,
        TestClock(Cell::new(Timestamp(1_000_000))),
        CachePolicy::default(),
    );
    let first = Response {
        status: 200,
        body: go_sds().into_bytes(),
        etag: Some("\"sds-1\"".into()),
        ..Response::default()
    };
    let transport = Scripted::new([first, ok(304, "")]);

    let (_, meta) = block_on(Connector::connect_cached(
        &dotkon(),
        &transport,
        TIMEOUTS,
        &cache,
    ))
    .unwrap();
    assert_eq!(meta.source, Source::Http);
    let (_, meta) = block_on(Connector::connect_cached(
        &dotkon(),
        &transport,
        TIMEOUTS,
        &cache,
    ))
    .unwrap();
    assert_eq!(
        (meta.source, transport.seen.borrow().len()),
        (Source::Cache, 1),
        "fresh: served without a request"
    );

    let clock = cache.clock();
    clock.0.set(Timestamp(1_000_000) + Duration::from_hours(2));
    let (connector, meta) = block_on(Connector::connect_cached(
        &dotkon(),
        &transport,
        TIMEOUTS,
        &cache,
    ))
    .unwrap();
    assert_eq!(meta.source, Source::Cache);
    assert_eq!(meta.fetched_at, clock.now(), "304 renews the entry");
    assert_eq!(
        transport.seen.borrow()[1].if_none_match.as_deref(),
        Some("\"sds-1\"")
    );
    assert!(
        connector
            .directory()
            .resolve("EventService", &["7.2"])
            .is_ok()
    );
}
