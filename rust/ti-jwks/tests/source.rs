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

//! The rules of the crate documentation against a scripted origin and a clock the test moves.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::time::Duration;

use futures_lite::future::block_on;
use ti_cache::{Cache, MemoryCacheStore};
use ti_jwks::http::{Request, Response, Transport, TransportError};
use ti_jwks::{Error, JwksSource, Limits, policy};
use ti_types::Timestamp;

const T0: Timestamp = Timestamp(1_700_000_000);
const URL: &str = "https://issuer.example/jwks";

struct TestClock(Cell<Timestamp>);

impl TestClock {
    fn now(&self) -> Timestamp {
        self.0.get()
    }

    fn advance(&self, by: Duration) {
        self.0.set(self.0.get() + by);
    }
}

/// An origin that answers from a script and records what it was asked.
#[derive(Default)]
struct Origin {
    answers: RefCell<VecDeque<Result<Response, TransportError>>>,
    asked: RefCell<Vec<Vec<(String, String)>>>,
}

impl Origin {
    fn then(&self, answer: Response) -> &Self {
        self.answers.borrow_mut().push_back(Ok(answer));
        self
    }

    fn fails(&self, error: &str) -> &Self {
        self.answers
            .borrow_mut()
            .push_back(Err(TransportError(error.into())));
        self
    }

    fn requests(&self) -> usize {
        self.asked.borrow().len()
    }
}

impl Transport for Origin {
    async fn get(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        assert_eq!(request.url, URL);
        self.asked.borrow_mut().push(
            request
                .headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
        );
        self.answers
            .borrow_mut()
            .pop_front()
            .expect("the origin was asked more often than scripted")
    }
}

const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn key(kid: &str, members: &str) -> String {
    format!(r#"{{"kty":"EC","crv":"P-256","kid":"{kid}","x":"{X}","y":"{Y}"{members}}}"#)
}

fn set(keys: &[String]) -> Vec<u8> {
    format!(r#"{{"keys":[{}]}}"#, keys.join(",")).into_bytes()
}

fn ok(body: Vec<u8>, headers: &[(&str, &str)]) -> Response {
    Response {
        status: 200,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        body,
    }
}

fn status(status: u16) -> Response {
    Response {
        status,
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn source<'a>(
    origin: &'a Origin,
    clock: &'a TestClock,
) -> JwksSource<MemoryCacheStore, impl Fn() -> Timestamp + 'a, &'a Origin> {
    JwksSource::new(
        URL,
        Cache::new(MemoryCacheStore::new(), move || clock.now(), policy()),
        origin,
    )
    .unwrap()
}

fn kids(keys: &[jwz::jwk::Jwk]) -> Vec<&str> {
    keys.iter().filter_map(|k| k.kid.as_deref()).collect()
}

/// The transport's TLS vouches for the origin only if it is the URL configured.
#[test]
fn the_set_comes_from_an_https_url_and_a_redirect_is_not_followed() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    for url in [
        "http://issuer.example/jwks",
        "https://",
        "issuer.example",
        "ftp://x",
    ] {
        let cache = Cache::new(MemoryCacheStore::new(), || clock.now(), policy());
        assert!(
            matches!(
                JwksSource::new(url, cache, &origin),
                Err(Error::NotHttps(_))
            ),
            "{url}"
        );
    }
    let cache = Cache::new(MemoryCacheStore::new(), || clock.now(), policy());
    assert!(JwksSource::new("HTTPS://issuer.example/jwks", cache, &origin).is_ok());

    origin.then(status(302)).then(status(500));
    let source = source(&origin, &clock);
    assert_eq!(block_on(source.set()), Err(Error::Status(302)));
    assert_eq!(block_on(source.set()), Err(Error::Status(500)));
}

/// What does not fit the limits or does not parse is refused and never stored, so the
/// next lookup asks again.
#[test]
fn a_set_over_the_limits_or_not_a_set_is_refused_and_not_stored() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let small = Limits {
        max_body: 300,
        max_keys: 1,
    };
    let source = source(&origin, &clock).with_limits(small);
    origin
        .then(ok(vec![b' '; 301], &[]))
        .then(ok(set(&[key("a", ""), key("b", "")]), &[]))
        .then(ok(b"{\"keys\":".to_vec(), &[]))
        .then(ok(vec![0xff], &[]))
        .then(ok(set(&[key("a", "")]), &[]));
    assert_eq!(block_on(source.set()), Err(Error::TooLarge(300)));
    assert_eq!(block_on(source.set()), Err(Error::TooManyKeys(1)));
    assert!(matches!(block_on(source.set()), Err(Error::Malformed(_))));
    assert!(matches!(block_on(source.set()), Err(Error::Malformed(_))));
    assert_eq!(block_on(source.set()).unwrap().keys.len(), 1);
    assert_eq!(origin.requests(), 5);
}

/// RFC 9111 §5.2.2.1: the set is fresh for the origin's `max-age`, raised to 5 minutes
/// and cut to 24 hours; one hour without one.
#[test]
fn rfc_9111_5_2_2_1_the_set_is_fresh_for_the_origins_max_age_within_bounds() {
    for (cache_control, lifetime) in [
        (Some("max-age=600"), 600),
        (Some("no-cache"), 300),
        (Some("max-age=999999"), 86_400),
        (None, 3_600),
    ] {
        let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
        let source = source(&origin, &clock);
        let headers: Vec<(&str, &str)> = cache_control
            .map(|v| vec![("Cache-Control", v)])
            .unwrap_or_default();
        origin
            .then(ok(set(&[key("a", "")]), &headers))
            .then(ok(set(&[key("a", "")]), &headers));
        block_on(source.set()).unwrap();
        clock.advance(Duration::from_secs(lifetime - 1));
        block_on(source.set()).unwrap();
        assert_eq!(origin.requests(), 1, "{cache_control:?}: fresh");
        clock.advance(Duration::from_secs(1));
        block_on(source.set()).unwrap();
        assert_eq!(
            origin.requests(),
            2,
            "{cache_control:?}: stale after {lifetime} s"
        );
    }
}

/// RFC 9110 §13.1.1, §13.1.3: a stale set is revalidated with its `ETag` and
/// `Last-Modified`, and a 304 keeps it for another lifetime.
#[test]
fn rfc_9110_13_1_a_stale_set_is_revalidated_with_its_validators() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let source = source(&origin, &clock);
    origin
        .then(ok(
            set(&[key("a", "")]),
            &[
                ("ETag", "\"v1\""),
                ("Last-Modified", "Tue, 03 Nov 2026 10:00:00 GMT"),
                ("Cache-Control", "max-age=600"),
            ],
        ))
        .then(Response {
            status: 304,
            headers: vec![("cache-control".into(), "max-age=900".into())],
            body: Vec::new(),
        });
    block_on(source.set()).unwrap();
    clock.advance(Duration::from_secs(600));
    assert_eq!(kids(&block_on(source.set()).unwrap().keys), ["a"]);
    let second = &origin.asked.borrow()[1];
    assert!(
        second.contains(&("If-None-Match".into(), "\"v1\"".into())),
        "{second:?}"
    );
    assert!(
        second.contains(&(
            "If-Modified-Since".into(),
            "Tue, 03 Nov 2026 10:00:00 GMT".into()
        )),
        "{second:?}"
    );
    clock.advance(Duration::from_secs(899));
    block_on(source.set()).unwrap();
    assert_eq!(origin.requests(), 2, "the 304's max-age counts");
}

/// A withdrawn key must stop verifying: past its lifetime the set is not served when the
/// origin fails.
#[test]
fn a_stale_set_is_not_served_when_the_origin_fails() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let source = source(&origin, &clock);
    origin.then(ok(set(&[key("a", "")]), &[])).fails("down");
    block_on(source.set()).unwrap();
    clock.advance(Duration::from_hours(1));
    assert_eq!(
        block_on(source.keys(Some("a"), "ES256")),
        Err(Error::Transport(TransportError("down".into())))
    );
}

/// A `kid` the set lacks fetches it again, at most once a minute: made-up `kid`s cost the
/// origin one request a minute.
#[test]
fn an_unknown_kid_fetches_the_set_again_at_most_once_a_minute() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let source = source(&origin, &clock);
    origin
        .then(ok(
            set(&[key("old", "")]),
            &[("Cache-Control", "max-age=86400")],
        ))
        .then(ok(
            set(&[key("old", ""), key("new", "")]),
            &[("Cache-Control", "max-age=86400")],
        ));
    assert_eq!(
        kids(&block_on(source.keys(Some("old"), "ES256")).unwrap()),
        ["old"]
    );
    assert_eq!(
        kids(&block_on(source.keys(Some("new"), "ES256")).unwrap()),
        ["new"]
    );
    assert_eq!(origin.requests(), 2, "rotation seen at once");

    for _ in 0..100 {
        assert!(matches!(
            block_on(source.keys(Some("made-up"), "ES256")),
            Err(Error::NoKey { .. })
        ));
    }
    assert_eq!(
        origin.requests(),
        2,
        "within the minute of the last refresh"
    );
    clock.advance(Duration::from_mins(1));
    origin.then(ok(set(&[key("new", "")]), &[]));
    assert!(block_on(source.keys(Some("made-up"), "ES256")).is_err());
    assert_eq!(origin.requests(), 3, "a minute later, one more");
    assert!(
        block_on(source.keys(None, "ES256")).is_ok(),
        "no kid, no refresh"
    );
    assert_eq!(origin.requests(), 3);
}

/// A fetched set replaces the stored one whole.
#[test]
fn a_fetched_set_replaces_the_stored_one_and_a_removed_key_is_gone() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let source = source(&origin, &clock);
    origin
        .then(ok(set(&[key("a", ""), key("b", "")]), &[]))
        .then(ok(set(&[key("b", "")]), &[]))
        .then(ok(set(&[key("b", "")]), &[]));
    assert!(block_on(source.keys(Some("a"), "ES256")).is_ok());
    clock.advance(Duration::from_hours(1));
    // The stale set is replaced; "a" is then unknown, which asks once more.
    assert_eq!(
        block_on(source.keys(Some("a"), "ES256")),
        Err(Error::NoKey {
            kid: Some("a".into()),
            alg: "ES256".into()
        })
    );
    assert_eq!(origin.requests(), 3);
}

/// RFC 7517 §4.2, RFC 7517 §4.3, RFC 7517 §4.4 and RFC 7517 §5: the keys for a token are those
/// of the set with its `kid` whose `use` and `key_ops` allow signatures and whose `alg`,
/// if stated, is the token's.
#[test]
fn rfc_7517_4_4_the_keys_fit_the_tokens_kid_alg_and_use() {
    let (origin, clock) = (Origin::default(), TestClock(Cell::new(T0)));
    let source = source(&origin, &clock);
    origin.then(ok(
        set(&[
            key("k", r#","use":"sig","alg":"ES256""#),
            key("k", r#","use":"enc""#),
            key("k", r#","alg":"ES384""#),
            key("k", r#","key_ops":["encrypt"]"#),
            key("k", r#","key_ops":["verify"]"#),
            key("other", ""),
        ]),
        &[],
    ));
    let keys = block_on(source.keys(Some("k"), "ES256")).unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].alg.as_deref(), Some("ES256"));
    assert_eq!(
        keys[1].key_ops.as_deref(),
        Some(&["verify".to_string()][..])
    );
    assert_eq!(block_on(source.keys(None, "ES256")).unwrap().len(), 3);
}

/// RFC 9110 §5.3: several field lines of one name are one value, joined with commas; a
/// `Cache-Control` split over two lines still counts.
#[test]
fn rfc_9110_5_3_field_lines_of_one_name_are_one_value() {
    let response = Response {
        status: 200,
        headers: vec![
            ("Cache-Control".into(), "public".into()),
            ("ETag".into(), "\"v1\"".into()),
            ("cache-control".into(), "max-age=600".into()),
        ],
        body: Vec::new(),
    };
    assert_eq!(
        response.header("CACHE-CONTROL").as_deref(),
        Some("public, max-age=600")
    );
    assert_eq!(response.header("x-missing"), None);
}
