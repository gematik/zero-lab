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

//! The checks of `.kon` configurations (`check`) and their redacted view (`config`), as
//! pure functions of what a host observed: one test per rule.

use base64::Engine as _;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use ti_connector_client::check::{
    self, Finding, Report, Status, Step, StepId, TcpFailure, TcpObservation, TlsObservation,
};
use ti_connector_client::config::{self, ConfigView};
use ti_connector_client::{Dotkon, Error, Fault, ServiceDirectory, TraceEntry, TransportError};
use ti_types::Timestamp;

const SERVER: &[u8] = include_bytes!("tls/server.pem");
const OTHER: &[u8] = include_bytes!("tls/other.pem");
const CA: &[u8] = include_bytes!("tls/ca.pem");
const CLIENT_P12: &[u8] = include_bytes!("tls/client.p12");
/// A brainpoolP256r1 client key, which ring cannot sign with.
const BRAINPOOL_P12: &[u8] = include_bytes!("../../ti-cli/tests/fixtures/identity/aut.p12");
const SDS: &[u8] = include_bytes!("fixtures/ehex-connector.sds");

/// 2027-01-01: every TLS fixture is valid then (2026 to 2036).
const NOW: Timestamp = Timestamp(1_798_761_600);
/// 2040-01-01: every fixture has expired.
const LATER: Timestamp = Timestamp(2_208_988_800);

fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

const BASIC: &str = r#"{"type": "basic", "username": "praxis", "password": "s3cret-pw"}"#;

fn json(credentials: &str, extra: &str) -> String {
    format!(
        r#"{{"url": "https://konnektor.test:8443", "mandantId": "M1", "workplaceId": "W1",
            "clientSystemId": "C1", "userId": "comfort-user-id", "credentials": {credentials} {extra}}}"#
    )
}

fn parse(json: &str) -> Dotkon {
    Dotkon::parse_with(json.as_bytes(), |name| {
        (name == "KON_PASSWORD").then(|| "from-env-pw".to_owned())
    })
    .unwrap()
}

fn pkcs12(data: &[u8], password: &str) -> String {
    format!(
        r#"{{"type": "pkcs12", "data": "{}", "password": "{password}"}}"#,
        b64(data)
    )
}

fn messages(step: &Step) -> String {
    step.findings
        .iter()
        .map(|f| {
            format!(
                "{:?} {} | {}",
                f.status,
                f.message,
                f.hint.as_deref().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn has(step: &Step, status: Status, text: &str) -> bool {
    step.findings.iter().any(|f| {
        f.status == status
            && format!("{} {}", f.message, f.hint.as_deref().unwrap_or("")).contains(text)
    })
}

fn file_step(json: &str, mode: Option<u32>) -> Step {
    let parsed = Dotkon::parse_with(json.as_bytes(), |_| Some("x".into()));
    check::file(&parsed, json.as_bytes(), mode)
}

// ---- view ---------------------------------------------------------------------------

/// `config show` must not reveal a secret: neither the password, the PKCS#12 bytes nor
/// the comfort signature's user ID, not even in part.
#[test]
fn the_view_carries_no_secret() {
    for credentials in [BASIC.to_owned(), pkcs12(CLIENT_P12, "s3cret-pw")] {
        let json = json(&credentials, "");
        let view = ConfigView::new(&parse(&json), json.as_bytes());
        let shown = serde_json::to_string(&view).unwrap();
        for secret in ["s3cret", "comfort-user-id", &b64(CLIENT_P12)[..16]] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        assert!(view.user_id_set);
    }
}

#[test]
fn the_view_tells_plain_secrets_from_environment_variables() {
    let json = json(
        r#"{"type": "basic", "username": "praxis", "password": "pre${KON_PASSWORD}"}"#,
        "",
    );
    let view = ConfigView::new(&parse(&json), json.as_bytes());
    assert_eq!(view.credentials.password.stored, "environment");
    assert_eq!(view.credentials.password.variables, ["KON_PASSWORD"]);
    assert_eq!(view.credentials.data.stored, "absent");
    assert_eq!(view.plain_secrets(), [] as [&str; 0]);
    let json = self::json(BASIC, "");
    let view = ConfigView::new(&parse(&json), json.as_bytes());
    assert_eq!(view.plain_secrets(), ["credentials.password"]);
}

#[test]
fn the_view_shows_the_client_certificate_and_the_trust_store() {
    let json = json(
        &pkcs12(CLIENT_P12, "00"),
        &format!(
            r#", "trustStore": ["{}", "{}"]"#,
            b64(&der(SERVER)),
            b64(&der(CA))
        ),
    );
    let view = ConfigView::new(&parse(&json), json.as_bytes());
    let client = view.credentials.client_certificate.unwrap();
    assert_eq!(client.error, None);
    assert!(
        client
            .certificate
            .unwrap()
            .subject
            .contains("Clientsystem TEST-ONLY")
    );
    assert_eq!(
        (client.key.as_deref(), client.key_usable),
        (Some("ECDSA P-256"), true)
    );
    let roles: Vec<&str> = view.trust_store.iter().map(|t| t.role).collect();
    assert_eq!(roles, ["pin", "ca"]);
    assert_eq!(
        view.trust_store[0].certificate.as_ref().unwrap().sha256,
        config::sha256(&der(SERVER))
    );
}

// ---- file ---------------------------------------------------------------------------

#[test]
fn an_invalid_file_fails_with_every_problem() {
    let step = file_step(r#"{"url": "https://k"}"#, Some(0o600));
    assert_eq!(step.status, Status::Fail, "{}", messages(&step));
    assert!(has(&step, Status::Fail, "\"mandantId\" is required"));
}

#[test]
fn a_file_others_may_read_is_a_warning() {
    let step = file_step(&json(r#"{"type": "none"}"#, ""), Some(0o100_644));
    assert!(has(&step, Status::Warn, "mode 0644"), "{}", messages(&step));
    assert!(has(&step, Status::Warn, "chmod 600"));
    let step = file_step(&json(r#"{"type": "none"}"#, ""), Some(0o600));
    assert_eq!(step.status, Status::Ok, "{}", messages(&step));
    let step = file_step(&json(r#"{"type": "none"}"#, ""), None);
    assert!(has(&step, Status::Skip, "not checked"));
}

#[test]
fn plain_secrets_in_the_file_are_a_warning() {
    let step = file_step(&json(BASIC, ""), Some(0o600));
    assert!(
        has(&step, Status::Warn, "credentials.password"),
        "{}",
        messages(&step)
    );
    let step = file_step(
        &json(
            r#"{"type": "basic", "username": "u", "password": "${KON_PASSWORD}"}"#,
            "",
        ),
        Some(0o600),
    );
    assert!(
        !has(&step, Status::Warn, "plain text"),
        "{}",
        messages(&step)
    );
}

/// http is allowed outside the production environment, with a warning.
#[test]
fn an_http_url_warns_and_fails_in_production() {
    let json = json(r#"{"type": "none"}"#, "").replace("https://", "http://");
    let step = file_step(&json, Some(0o600));
    assert_eq!(step.status, Status::Warn, "{}", messages(&step));
    assert!(has(&step, Status::Warn, "unencrypted"));
    let pu = self::json(r#"{"type": "none"}"#, r#", "env": "pu""#).replace("https://", "http://");
    let step = file_step(&pu, Some(0o600));
    assert!(has(&step, Status::Fail, "env pu"), "{}", messages(&step));
}

#[test]
fn over_http_basic_warns_and_pkcs12_fails() {
    let http = r#", "url": "http://konnektor.test""#;
    let step = auth_step(BASIC, http, &directory(), NOW);
    assert!(
        has(&step, Status::Warn, "unencrypted"),
        "{}",
        messages(&step)
    );
    let step = auth_step(&pkcs12(CLIENT_P12, "00"), http, &directory(), NOW);
    assert!(
        has(&step, Status::Fail, "TLS handshake"),
        "{}",
        messages(&step)
    );
}

// ---- tcp ----------------------------------------------------------------------------

#[test]
fn tcp_failures_name_what_to_check() {
    let step = |result| {
        check::tcp(&TcpObservation {
            target: "konnektor.test:8443".into(),
            result,
        })
    };
    assert_eq!(step(Ok("10.0.0.1:8443".into())).status, Status::Ok);
    assert!(has(
        &step(Err(TcpFailure::Resolve("x".into()))),
        Status::Fail,
        "DNS"
    ));
    assert!(has(
        &step(Err(TcpFailure::Refused("x".into()))),
        Status::Fail,
        "port"
    ));
    assert!(has(
        &step(Err(TcpFailure::Timeout("x".into()))),
        Status::Fail,
        "firewall"
    ));
}

// ---- tls ----------------------------------------------------------------------------

fn seen(leaf: &[u8], verified: Result<(), String>) -> TlsObservation {
    TlsObservation {
        chain: vec![der(leaf)],
        verified: Some(verified),
        handshake: Ok(()),
    }
}

fn tls_step(extra: &str, observation: &TlsObservation) -> Step {
    check::tls(&parse(&json(BASIC, extra)), observation, NOW)
}

fn trust(pem: &[u8]) -> String {
    format!(r#", "trustStore": ["{}"]"#, b64(&der(pem)))
}

#[test]
fn the_pinned_certificate_is_trusted() {
    let step = tls_step(&trust(SERVER), &seen(SERVER, Ok(())));
    assert_eq!(step.status, Status::Ok, "{}", messages(&step));
    assert!(has(&step, Status::Ok, "matches the pinned certificate"));
    assert!(has(&step, Status::Ok, &config::sha256(&der(SERVER))));
}

/// A changed server certificate fails and shows both SHA-256 values.
#[test]
fn another_certificate_than_the_pinned_one_fails() {
    let step = tls_step(&trust(OTHER), &seen(SERVER, Err("UnknownIssuer".into())));
    assert_eq!(step.status, Status::Fail, "{}", messages(&step));
    assert!(has(&step, Status::Fail, &config::sha256(&der(OTHER))));
    assert!(has(&step, Status::Ok, &config::sha256(&der(SERVER))));
    assert!(has(&step, Status::Fail, "replace the pin"));
}

#[test]
fn a_ca_of_the_trust_store_is_trusted() {
    let step = tls_step(&trust(CA), &seen(SERVER, Ok(())));
    assert!(
        has(&step, Status::Ok, "CA of the trustStore"),
        "{}",
        messages(&step)
    );
    let step = tls_step(&trust(CA), &seen(OTHER, Err("UnknownIssuer".into())));
    assert!(
        has(&step, Status::Fail, "not trusted"),
        "{}",
        messages(&step)
    );
}

#[test]
fn without_a_pin_the_system_trust_store_is_a_warning() {
    let step = tls_step("", &seen(SERVER, Ok(())));
    assert!(has(&step, Status::Warn, "no pin"), "{}", messages(&step));
}

#[test]
fn insecure_skip_verify_warns_and_fails_in_production() {
    let step = tls_step(r#", "insecureSkipVerify": true"#, &seen(SERVER, Ok(())));
    assert_eq!(step.status, Status::Warn, "{}", messages(&step));
    let step = tls_step(
        r#", "insecureSkipVerify": true, "env": "pu""#,
        &seen(SERVER, Ok(())),
    );
    assert!(has(&step, Status::Fail, "env pu"), "{}", messages(&step));
}

#[test]
fn an_expired_server_certificate_is_a_warning() {
    let step = check::tls(
        &parse(&json(BASIC, &trust(SERVER))),
        &seen(SERVER, Ok(())),
        LATER,
    );
    assert!(has(&step, Status::Warn, "expired"), "{}", messages(&step));
}

#[test]
fn no_server_certificate_fails() {
    let observation = TlsObservation {
        chain: Vec::new(),
        verified: None,
        handshake: Err("received corrupt message".into()),
    };
    assert_eq!(tls_step("", &observation).status, Status::Fail);
}

// ---- auth ---------------------------------------------------------------------------

fn directory() -> Result<ServiceDirectory, Error> {
    ServiceDirectory::parse(SDS)
}

fn auth_step(
    credentials: &str,
    extra: &str,
    sds: &Result<ServiceDirectory, Error>,
    now: Timestamp,
) -> Step {
    let dotkon = parse(&json(credentials, extra));
    let client = match &dotkon.credentials {
        ti_connector_client::Credentials::Pkcs12 { data, password } => {
            Some(config::client_certificate(data, password))
        }
        _ => None,
    };
    check::auth(&dotkon, client.as_ref(), None, Some(sds), now)
}

#[test]
fn credentials_of_type_none_warn_and_fail_in_production() {
    let step = auth_step(r#"{"type": "none"}"#, "", &directory(), NOW);
    assert_eq!(step.status, Status::Warn, "{}", messages(&step));
    let step = auth_step(r#"{"type": "none"}"#, r#", "env": "pu""#, &directory(), NOW);
    assert!(has(&step, Status::Fail, "env pu"), "{}", messages(&step));
}

#[test]
fn a_refused_client_fails_with_a_hint_for_its_credentials() {
    let refused = Err(Error::HttpStatus {
        status: 401,
        body: String::new(),
    });
    let step = auth_step(BASIC, "", &refused, NOW);
    assert!(has(&step, Status::Fail, "HTTP 401"), "{}", messages(&step));
    assert!(has(&step, Status::Fail, "username and password"));
    let alert = Err(Error::Transport(TransportError {
        message: "io: received fatal alert: CertificateRequired".into(),
        timed_out: false,
    }));
    let step = auth_step(&pkcs12(CLIENT_P12, "00"), "", &alert, NOW);
    assert!(
        has(&step, Status::Fail, "TLS handshake"),
        "{}",
        messages(&step)
    );
    assert!(has(&step, Status::Fail, "assigns this client certificate"));
}

#[test]
fn the_client_certificate_is_checked_before_it_is_offered() {
    let step = auth_step(&pkcs12(CLIENT_P12, "00"), "", &directory(), NOW);
    assert_eq!(step.status, Status::Ok, "{}", messages(&step));
    assert!(has(&step, Status::Ok, "Clientsystem TEST-ONLY"));
    let step = auth_step(&pkcs12(CLIENT_P12, "wrong"), "", &directory(), NOW);
    assert!(
        has(&step, Status::Fail, "wrong password"),
        "{}",
        messages(&step)
    );
    let step = auth_step(&pkcs12(CLIENT_P12, "00"), "", &directory(), LATER);
    assert!(has(&step, Status::Fail, "expired"), "{}", messages(&step));
    let step = auth_step(&pkcs12(BRAINPOOL_P12, "00"), "", &directory(), NOW);
    assert!(
        has(
            &step,
            Status::Fail,
            "cannot sign with ECDSA brainpoolP256r1"
        ),
        "{}",
        messages(&step)
    );
}

// ---- sds, context, cards ------------------------------------------------------------

#[test]
fn the_service_directory_names_the_product_and_the_services() {
    let step = check::sds(&directory());
    assert!(has(&step, Status::Ok, "Konnektor"), "{}", messages(&step));
    assert!(has(&step, Status::Ok, "CardService"), "{}", messages(&step));
}

fn fault(code: i64) -> Error {
    Error::Fault(Fault {
        code: "soap:Server".into(),
        message: "Fehler".into(),
        trace: vec![TraceEntry {
            code: Some(code),
            error_text: None,
            error_type: None,
            severity: None,
            event_id: None,
            comp_type: None,
            detail: None,
        }],
    })
}

/// Konnektors may answer an unknown ID with 4021, so its hint names all three.
#[test]
fn a_refused_call_context_names_the_ids_to_compare() {
    let dotkon = parse(&json(BASIC, ""));
    let step = check::context(&dotkon, &Err(fault(4021)));
    assert_eq!(step.status, Status::Fail);
    for id in [
        "mandantId",
        "clientSystemId",
        "workplaceId",
        "M1",
        "C1",
        "W1",
    ] {
        assert!(has(&step, Status::Fail, id), "{id}: {}", messages(&step));
    }
    let step = check::context(&dotkon, &Err(fault(4005)));
    assert!(has(
        &step,
        Status::Fail,
        "does not know the .kon clientSystemId"
    ));
}

#[test]
fn no_cards_is_a_warning() {
    assert_eq!(check::cards(&[]).status, Status::Warn);
}

// ---- report -------------------------------------------------------------------------

#[test]
fn a_failed_step_skips_the_rest() {
    let mut report = Report::default();
    assert!(report.push(Step::new(StepId::File, vec![Finding::ok("valid")])));
    assert!(!report.push(Step::new(
        StepId::Tcp,
        vec![Finding::new(Status::Fail, "refused", None)]
    )));
    let report = report.finish();
    assert_eq!(report.status, Status::Fail);
    let ids: Vec<&str> = report.steps.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(
        ids,
        ["file", "tcp", "tls", "auth", "sds", "context", "cards"]
    );
    assert!(report.steps[2..].iter().all(|s| s.status == Status::Skip));
    assert!(messages(&report.steps[2]).contains("the tcp step failed"));
}

#[test]
fn warnings_make_a_warning_report() {
    let mut report = Report::default();
    report.push(Step::new(
        StepId::File,
        vec![Finding::new(Status::Warn, "mode 0644", None)],
    ));
    assert_eq!(report.finish().status, Status::Warn);
}
