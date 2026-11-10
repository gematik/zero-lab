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

//! `ti connector …` against a fake Konnektor on loopback (plain HTTP, the eHEX service
//! directory with rewritten endpoints, answers shaped like the Konnektor's): every
//! command's JSON against its schema, exit codes, and restricted card types.

mod support;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use support::{assert_conforms, assert_old_store_untouched, seed_old_store};

const SDS: &str = include_str!("../../ti-connector-client/tests/fixtures/ehex-connector.sds");
/// Answers recorded from an eHEX Konnektor (ti-connector-client's replayed session).
const RECORDED_JOB: &str = include_str!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/07-GetJobNumber.response-200.xml"
);
const RECORDED_CADES: &str = include_str!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/08-SignDocument.response-200.xml"
);
const RECORDED_VERIFY: &str = include_str!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/09-VerifyDocument.response-200.xml"
);
const RECORDED_ENCRYPT: &str = include_str!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/14-EncryptDocument.response-200.xml"
);
const RECORDED_DECRYPT: &str = include_str!(
    "../../ti-connector-client/tests/fixtures/recorded/ehex-6.0.2/15-DecryptDocument.response-200.xml"
);
/// An OpenSSL-generated certificate with an admission (ti-pki's test PKI).
const EE_ARZT: &str = include_str!("../../ti-pki/tests/pki/ee-arzt.pem");

fn envelope(body: &str) -> String {
    format!(
        r#"<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>{body}</soap:Body></soap:Envelope>"#
    )
}

const OK: &str = r#"<C:Status xmlns:C="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><C:Result>OK</C:Result></C:Status>"#;

fn card(handle: &str, kind: &str, iccsn: &str, slot: u8, holder: &str) -> String {
    format!(
        "<Card><CardHandle>{handle}</CardHandle><CardType>{kind}</CardType><Iccsn>{iccsn}</Iccsn>\
         <CtId>CT1</CtId><SlotId>{slot}</SlotId><InsertTime>2026-09-01T08:00:00Z</InsertTime>\
         <CardHolderName>{holder}</CardHolderName></Card>"
    )
}

fn fault(code: u32, text: &str) -> String {
    envelope(&format!(
        "<soap:Fault><faultcode>soap:Server</faultcode><faultstring>{text}</faultstring><detail>\
         <E:Error xmlns:E=\"http://ws.gematik.de/tel/error/v2.0\"><E:Trace><E:Code>{code}</E:Code>\
         <E:ErrorText>{text}</E:ErrorText></E:Trace></E:Error></detail></soap:Fault>"
    ))
}

/// UUID-shaped, as many Konnektors hand out: the card tables shorten it.
const KT_HANDLE: &str = "card-kt-0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b";

/// The HBA; a Konnektor that reports no ICCSN leaves the element out.
fn hba_card(iccsn: Option<&str>) -> String {
    let xml = card(
        "card-hba",
        "HBA",
        iccsn.unwrap_or_default(),
        2,
        "Dr. Arzt TEST-ONLY",
    );
    match iccsn {
        Some(_) => xml,
        None => xml.replace("<Iccsn></Iccsn>", ""),
    }
}

/// The fake's cards; GetCards filters by the card type in the request, if any.
fn cards(body: &str, hba_iccsn: Option<&str>) -> String {
    [
        (
            "SMC-B",
            card(
                "card-smcb",
                "SMC-B",
                "80276001011699910102",
                1,
                "Praxis TEST-ONLY",
            ),
        ),
        ("HBA", hba_card(hba_iccsn)),
        (
            "SMC-KT",
            card(KT_HANDLE, "SMC-KT", "80276001011699910104", 3, "Terminal"),
        ),
    ]
    .into_iter()
    .filter(|(kind, _)| !body.contains("CardType>") || body.contains(&format!(">{kind}<")))
    .map(|(_, xml)| xml)
    .collect()
}

/// The answer to one request: `(status, body)`.
fn answer(path: &str, action: &str, body: &str, behavior: &Behavior) -> (u16, String) {
    if path == "/connector.sds" {
        return (200, SDS.to_owned());
    }
    let operation = action
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .trim_matches('"');
    let cards = cards(body, behavior.hba_iccsn.as_deref());
    let der_b64: String = EE_ARZT
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    if let Some(answer) = document_answer(operation, body) {
        return answer;
    }
    let response = match operation {
        "GetCards" => format!(
            "<E:GetCardsResponse xmlns:E=\"e\">{OK}<Cards>{cards}</Cards></E:GetCardsResponse>"
        ),
        "GetResourceInformation" if body.contains("card-kt") => {
            return (500, fault(4101, "Karten-Handle ungültig"));
        }
        "GetResourceInformation" if body.contains("card-") => format!(
            "<E:GetResourceInformationResponse xmlns:E=\"e\">{OK}{}</E:GetResourceInformationResponse>",
            card(
                "card-smcb",
                "SMC-B",
                "80276001011699910102",
                1,
                "Praxis TEST-ONLY"
            )
        ),
        "GetResourceInformation" => format!(
            "<E:GetResourceInformationResponse xmlns:E=\"e\">{OK}<Connector>\
             <VPNTIStatus><ConnectionStatus>Online</ConnectionStatus><Timestamp>2026-09-01T08:00:00Z</Timestamp></VPNTIStatus>\
             <VPNSISStatus><ConnectionStatus>Offline</ConnectionStatus><Timestamp>2026-09-01T08:00:00Z</Timestamp></VPNSISStatus>\
             <OperatingState><ErrorState><ErrorCondition>EC_Time_Sync_Not_Successful</ErrorCondition><Severity>Warning</Severity>\
             <Type>Operation</Type><Value>true</Value><ValidFrom>2026-09-01T08:00:00Z</ValidFrom></ErrorState></OperatingState>\
             </Connector></E:GetResourceInformationResponse>"
        ),
        "ReadCardCertificate" if body.contains("card-kt") => {
            return (500, fault(4001, "Interner Fehler"));
        }
        "ReadCardCertificate" if body.contains(">RSA<") => {
            return (500, fault(4002, "Kartenobjekt nicht vorhanden"));
        }
        "ReadCardCertificate" => format!(
            "<C:ReadCardCertificateResponse xmlns:C=\"c\">{OK}<X509DataInfoList><X509DataInfo><CertRef>C.AUT</CertRef>\
             <X509Data><X509IssuerSerial><X509IssuerName>CN=CA</X509IssuerName><X509SerialNumber>1</X509SerialNumber>\
             </X509IssuerSerial><X509SubjectName>CN=Dr. Arzt</X509SubjectName><X509Certificate>{der_b64}</X509Certificate>\
             </X509Data></X509DataInfo></X509DataInfoList></C:ReadCardCertificateResponse>"
        ),
        "CheckCertificateExpiration" => format!(
            "<C:CheckCertificateExpirationResponse xmlns:C=\"c\">{OK}<CertificateExpiration><CtID>CT1</CtID>\
             <CardHandle>card-smcb</CardHandle><ICCSN>80276001011699910102</ICCSN><subject_commonName>Praxis</subject_commonName>\
             <serialNumber>42</serialNumber><validity>2029-11-06</validity></CertificateExpiration></C:CheckCertificateExpirationResponse>"
        ),
        "VerifyCertificate" => format!(
            "<C:VerifyCertificateResponse xmlns:C=\"c\">{OK}<VerificationStatus><VerificationResult>INVALID</VerificationResult>\
             <Error><MessageID>m</MessageID><Timestamp>t</Timestamp><Trace><EventID>e</EventID><Instance>i</Instance>\
             <LogReference>l</LogReference><CompType>Konnektor</CompType><Code>4023</Code><Severity>Error</Severity>\
             <ErrorType>Security</ErrorType><ErrorText>Zertifikat widerrufen</ErrorText></Trace></Error>\
             </VerificationStatus><RoleList><Role>1.2.276.0.76.4.30</Role></RoleList></C:VerifyCertificateResponse>"
        ),
        // SMC-B verified; HBA: PIN.CH needs entry, PIN.QES is blocked.
        "GetPinStatus" => {
            let (status, tries) = if body.contains("card-smcb") {
                ("VERIFIED", "")
            } else if body.contains("PIN.QES") {
                ("BLOCKED", "<LeftTries>0</LeftTries>")
            } else {
                ("VERIFIABLE", "<LeftTries>3</LeftTries>")
            };
            format!(
                "<C:GetPinStatusResponse xmlns:C=\"c\">{OK}<PinStatus>{status}</PinStatus>{tries}</C:GetPinStatusResponse>"
            )
        }
        // A workplace whose card terminals are all remote, without a Remote-PIN-KT.
        "VerifyPin" if body.contains("W-REMOTE") => {
            return (
                500,
                fault(
                    4092,
                    "Remote-PIN-KT benötigt aber für diesen Arbeitsplatz nicht definiert",
                ),
            );
        }
        "VerifyPin" => format!(
            "<C:VerifyPinResponse xmlns:C=\"c\">{OK}<PinResult>REJECTED</PinResult><LeftTries>2</LeftTries></C:VerifyPinResponse>"
        ),
        "ChangePin" => format!(
            "<C:ChangePinResponse xmlns:C=\"c\">{OK}<PinResult>OK</PinResult></C:ChangePinResponse>"
        ),
        other => return (500, fault(4000, &format!("unexpected {other}"))),
    };
    (200, envelope(&response))
}

/// The answers to the signature, encryption and comfort signature operations.
fn document_answer(operation: &str, body: &str) -> Option<(u16, String)> {
    Some(match operation {
        "GetJobNumber" => (200, RECORDED_JOB.to_owned()),
        "SignDocument" if body.contains("http://uri.etsi.org/02778/3") => (
            200,
            envelope(&format!(
                "<S:SignDocumentResponse xmlns:S=\"s\" xmlns:D=\"urn:oasis:names:tc:dss:1.0:core:schema\"><S:SignResponse RequestID=\"request-0\">{OK}\
             <D:SignatureObject><D:Base64Signature Type=\"http://uri.etsi.org/02778/3\">JVBERi1zaWduZWQ=</D:Base64Signature></D:SignatureObject>\
             </S:SignResponse></S:SignDocumentResponse>"
            )),
        ),
        "SignDocument" => (200, RECORDED_CADES.to_owned()),
        "VerifyDocument" => (200, RECORDED_VERIFY.to_owned()),
        "EncryptDocument" => (200, RECORDED_ENCRYPT.to_owned()),
        "DecryptDocument" => (200, RECORDED_DECRYPT.to_owned()),
        "ActivateComfortSignature" => (
            200,
            envelope(&format!(
                "<S:ActivateComfortSignatureResponse xmlns:S=\"s\">{OK}<S:SignatureMode>COMFORT</S:SignatureMode></S:ActivateComfortSignatureResponse>"
            )),
        ),
        "GetSignatureMode" => (
            200,
            envelope(&format!(
                "<S:GetSignatureModeResponse xmlns:S=\"s\">{OK}<S:ComfortSignatureStatus>ENABLED</S:ComfortSignatureStatus>\
             <S:ComfortSignatureMax>250</S:ComfortSignatureMax><S:ComfortSignatureTimer>PT24H</S:ComfortSignatureTimer>\
             <S:SessionInfo><S:SignatureMode>COMFORT</S:SignatureMode><S:CountRemaining>249</S:CountRemaining><S:TimeRemaining>PT23H</S:TimeRemaining></S:SessionInfo>\
             </S:GetSignatureModeResponse>"
            )),
        ),
        "DeactivateComfortSignature" => (
            200,
            envelope(&format!(
                "<S:DeactivateComfortSignatureResponse xmlns:S=\"s\">{OK}</S:DeactivateComfortSignatureResponse>"
            )),
        ),
        _ => return None,
    })
}

/// What a fake Konnektor reports and records, apart from the fixed answers.
#[derive(Clone)]
struct Behavior {
    hba_iccsn: Option<String>,
    activations: Arc<AtomicUsize>,
    deactivations: Arc<AtomicUsize>,
    /// Every call, as its action and body.
    calls: Arc<Mutex<Vec<(String, String)>>>,
    /// The ID the HBA's comfort session runs under: a call on the HBA with another one is
    /// refused (gemSpec_Kon TAB_KON_514-01, 4018).
    raised_for: Arc<Mutex<Option<String>>>,
}

/// The `UserId` of a call's context.
fn user_id_of(body: &str) -> Option<&str> {
    let start = body.find("UserId>")? + "UserId>".len();
    let end = start + body[start..].find('<')?;
    Some(&body[start..end])
}

/// `GetSignatureMode` for a user ID with no session on the card.
fn mode_without_session() -> String {
    envelope(&format!(
        "<S:GetSignatureModeResponse xmlns:S=\"s\">{OK}<S:ComfortSignatureStatus>ENABLED</S:ComfortSignatureStatus>\
         <S:ComfortSignatureMax>250</S:ComfortSignatureMax><S:ComfortSignatureTimer>PT24H</S:ComfortSignatureTimer>\
         </S:GetSignatureModeResponse>"
    ))
}

impl Behavior {
    /// A call under another ID was refused by then, so this is the caller's session.
    fn has_session(&self) -> bool {
        self.raised_for.lock().unwrap().is_some()
    }

    fn standard() -> Self {
        Behavior {
            hba_iccsn: Some("80276001011699910103".into()),
            activations: Arc::default(),
            deactivations: Arc::default(),
            calls: Arc::default(),
            raised_for: Arc::default(),
        }
    }

    /// What the HBA's raised session means for this call: a 4018 for another user's.
    fn refusal(&self, action: &str, body: &str) -> Option<String> {
        let mut raised = self.raised_for.lock().unwrap();
        if action.contains("DeactivateComfortSignature") {
            *raised = None;
            return None;
        }
        if action.contains("ActivateComfortSignature") {
            *raised = user_id_of(body).map(str::to_owned);
            return None;
        }
        let holder = raised.as_deref()?;
        (body.contains("card-hba") && user_id_of(body) != Some(holder)).then(|| {
            fault(
                4018,
                "Der HBAx hat mindestens eine Kartensitzung zu einer anderen UserId",
            )
        })
    }
}

fn handle(stream: impl Read + Write, behavior: &Behavior) -> Option<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let path = request_line.split_whitespace().nth(1)?.to_owned();
    let (mut length, mut action) = (0, String::new());
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().ok()?,
            "soapaction" => value.trim().clone_into(&mut action),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    if action.contains("ActivateComfortSignature") && !action.contains("Deactivate") {
        behavior.activations.fetch_add(1, Ordering::SeqCst);
    }
    if action.contains("DeactivateComfortSignature") {
        behavior.deactivations.fetch_add(1, Ordering::SeqCst);
    }
    let body = String::from_utf8_lossy(&body);
    behavior
        .calls
        .lock()
        .unwrap()
        .push((action.clone(), body.clone().into_owned()));
    let (status, response) = match behavior.refusal(&action, &body) {
        Some(refused) => (500, refused),
        None if action.contains("GetSignatureMode") && !behavior.has_session() => {
            (200, mode_without_session())
        }
        None => answer(&path, &action, &body, behavior),
    };
    let stream = reader.get_mut();
    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .ok()?;
    stream.flush().ok()
}

/// A fake Konnektor serving until the test process ends, and a `.kon` file for it.
struct Fake {
    dir: PathBuf,
    kon: PathBuf,
    activations: Arc<AtomicUsize>,
    #[cfg(unix)]
    deactivations: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<(String, String)>>>,
    raised_for: Arc<Mutex<Option<String>>>,
}

impl Fake {
    /// Over plain http, which `config test` refuses.
    fn start(name: &str) -> Self {
        Fake::start_with(name, Behavior::standard())
    }

    /// A fake whose HBA reports `iccsn`, or none.
    fn start_with_hba_iccsn(name: &str, iccsn: Option<&str>) -> Self {
        Fake::start_with(
            name,
            Behavior {
                hba_iccsn: iccsn.map(str::to_owned),
                ..Behavior::standard()
            },
        )
    }

    fn start_with(name: &str, behavior: Behavior) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = behavior.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let behavior = behavior.clone();
                std::thread::spawn(move || handle(stream, &behavior));
            }
        });
        Fake::with_kon(name, &format!("http://127.0.0.1:{port}"), "", &served)
    }

    /// Over TLS with ti-connector-client's test server certificate, pinned in the
    /// `.kon` file.
    fn start_tls(name: &str) -> Self {
        let config = tls_server_config();
        let behavior = Behavior::standard();
        let served = behavior.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for socket in listener.incoming().flatten() {
                let config = config.clone();
                let behavior = behavior.clone();
                std::thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(config).ok()?;
                    handle(rustls::StreamOwned::new(conn, socket), &behavior)
                });
            }
        });
        let pin = format!(
            r#""trustStore": ["{}"], "#,
            base64ct_encode(&tls_der(TLS_SERVER))
        );
        Fake::with_kon(name, &format!("https://127.0.0.1:{port}"), &pin, &served)
    }

    fn with_kon(name: &str, url: &str, extra: &str, behavior: &Behavior) -> Self {
        let dir = std::env::temp_dir().join(format!("ti-connector-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/telematik/connectors")).unwrap();
        let kon = dir.join("config/telematik/connectors/praxis.kon");
        std::fs::write(
            &kon,
            format!(
                r#"{{"url": "{url}", {extra}"rewriteServiceEndpoints": true,
                    "mandantId": "M1", "workplaceId": "W1", "clientSystemId": "C1", "env": "ru",
                    "credentials": {{"type": "basic", "username": "u", "password": "${{KON_TEST_PASSWORD}}"}}}}"#
            ),
        )
        .unwrap();
        Fake {
            dir,
            kon,
            activations: behavior.activations.clone(),
            #[cfg(unix)]
            deactivations: behavior.deactivations.clone(),
            calls: behavior.calls.clone(),
            raised_for: behavior.raised_for.clone(),
        }
    }

    fn ti(&self, args: &[&str]) -> Output {
        self.ti_with(args, &[])
    }

    /// Forgets the calls so far.
    fn forget_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    /// Asserts that since [`forget_calls`](Self::forget_calls) the card was not asked: no
    /// call of the signature service, and `id`, when given, in no call at all.
    fn assert_card_not_asked(&self, id: Option<&str>) {
        for (action, body) in self.calls.lock().unwrap().iter() {
            assert!(
                ![
                    "SignDocument",
                    "GetSignatureMode",
                    "ActivateComfortSignature"
                ]
                .iter()
                .any(|operation| action.contains(operation)),
                "{action}"
            );
            if let Some(id) = id {
                assert!(!body.contains(id), "the ID reached the Konnektor: {action}");
            }
        }
    }

    fn ti_with(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ti"));
        cmd.args(args)
            .current_dir(&self.dir)
            .env_remove("TI_FORMAT")
            .env_remove("TI_CONNECTOR_CONFIG")
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("TI_CACHE_DIR", self.dir.join("cache"))
            .env("XDG_CACHE_HOME", self.dir.join("xdg-cache"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env_remove("TI_PROFILE")
            .env_remove("TI_STATE_DIR")
            .env_remove("TI_COMFORT_USER_ID")
            .env("KON_TEST_PASSWORD", "p");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    fn json(&self, schema: &str, args: &[&str]) -> (Value, Option<i32>) {
        let mut all = vec!["--format", "json", "connector", "-c", "praxis"];
        all.extend_from_slice(args);
        let out = self.ti(&all);
        assert!(
            !out.stdout.is_empty(),
            "{schema}: no output; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_conforms(schema, &out.stdout);
        (
            serde_json::from_slice(&out.stdout).unwrap(),
            out.status.code(),
        )
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn every_connector_command_matches_its_schema() {
    let fake = Fake::start("schema");

    let (configs, _) = fake.json("connector config list", &["config", "list"]);
    assert_eq!(configs["configurations"][0]["name"], "praxis");
    assert_eq!(configs["configurations"][0]["context"], "M1/W1/C1");

    let (info, _) = fake.json("connector get info", &["get", "info"]);
    assert_eq!(
        (info["credentials"].as_str(), info["environment"].as_str()),
        (Some("basic"), Some("ref"))
    );
    assert_eq!(info["product"]["vendor_id"], "EHEXP");

    let (services, _) = fake.json("connector get services", &["get", "services"]);
    let card_service = services["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "CardService")
        .unwrap();
    let used: Vec<&str> = card_service["versions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["used"] == true)
        .map(|v| v["version"].as_str().unwrap())
        .collect();
    assert_eq!(used, ["8.1.2", "8.2.1"]);

    let (cards, _) = fake.json("connector get cards", &["get", "cards"]);
    assert_eq!(cards["cards"].as_array().unwrap().len(), 3);

    let (certificates, _) = fake.json(
        "connector get certificates",
        &["get", "certificates", "80276001011699910102"],
    );
    assert_eq!(
        certificates["certificates"][0]["telematik_id"],
        "80276001081234567890"
    );
    assert_eq!(
        certificates["certificates"].as_array().unwrap().len(),
        1,
        "no RSA keys"
    );

    let (status, _) = fake.json("connector get status", &["get", "status"]);
    assert_eq!(status["vpn_ti"]["status"], "Online");
    assert_eq!(status["errors"][0]["active"], true);

    let (identities, _) = fake.json("connector get identities", &["get", "identities"]);
    assert_eq!(
        identities["identities"].as_array().unwrap().len(),
        2,
        "HBA and SMC-B"
    );

    fake.json(
        "connector get expiration",
        &["get", "expiration", "card-smcb"],
    );
    fake.json(
        "connector describe card",
        &["describe", "card", "card-smcb"],
    );
    let (inspected, _) = fake.json(
        "pki inspect",
        &["describe", "certificate", "card-hba", "c.aut"],
    );
    assert!(
        inspected["source"]
            .as_str()
            .unwrap()
            .starts_with("C.AUT ECC of HBA")
    );

    let (pin, code) = fake.json("connector pin", &["verify", "pin", "card-smcb"]);
    assert_eq!(
        (pin["pin"].as_str(), pin["result"].as_str(), code),
        (Some("PIN.SMC"), Some("REJECTED"), Some(1))
    );
    let (pin, code) = fake.json("connector pin", &["change", "pin", "card-hba", "pin.ch"]);
    assert_eq!((pin["result"].as_str(), code), (Some("OK"), Some(0)));

    let (verdict, code) = fake.json(
        "connector verify certificate",
        &["verify", "certificate", "card-smcb", "C.AUT"],
    );
    assert_eq!(
        (verdict["result"].as_str(), code),
        (Some("INVALID"), Some(1))
    );
    assert_eq!(verdict["errors"][0], "4023 Zertifikat widerrufen");

    let (selected, _) = fake.json("connector use", &["use", "praxis"]);
    assert_eq!(selected["path"], path_str(&fake.kon));
}

#[test]
fn restricted_cards_and_usage_errors_say_what_to_do() {
    let fake = Fake::start("errors");
    let out = fake.ti(&[
        "--format",
        "json",
        "connector",
        "-c",
        "praxis",
        "get",
        "certificates",
        KT_HANDLE,
    ]);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(
        (error["error"]["kind"].as_str(), out.status.code()),
        (Some("card_restricted"), Some(3))
    );
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SMC-KT")
    );

    let out = fake.ti(&[
        "--format",
        "json",
        "connector",
        "-c",
        "praxis",
        "verify",
        "pin",
        "card-hba",
    ]);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(
        (error["error"]["kind"].as_str(), out.status.code()),
        (Some("pin_type"), Some(2))
    );
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("PIN.CH, PIN.QES")
    );

    let out = fake.ti(&[
        "--format",
        "json",
        "connector",
        "-c",
        "nowhere",
        "get",
        "cards",
    ]);
    let error: Value = serde_json::from_slice(&out.stderr).unwrap();
    assert_eq!(
        (error["error"]["kind"].as_str(), out.status.code()),
        (Some("connector_config"), Some(2))
    );
}

/// gemSpec_Kon TUC_KON_012 error 4092 keeps its code and text, and gains a hint at the
/// .kon workplace and the Konnektor's information model, in JSON and in the text.
#[test]
fn kon_4092_verify_pin_without_remote_pin_kt_hints_the_workplace() {
    let fake = Fake::start("remote-pin");
    let praxis = std::fs::read_to_string(&fake.kon).unwrap();
    std::fs::write(
        fake.kon.with_file_name("remote.kon"),
        praxis.replace(r#""W1""#, r#""W-REMOTE""#),
    )
    .unwrap();
    let args = ["connector", "-c", "remote", "verify", "pin", "card-smcb"];
    let out = fake.ti(&[&["--format", "json"][..], &args].concat());
    // The PIN prompt comes first on stderr, the error document last.
    let stderr = String::from_utf8(out.stderr).unwrap();
    let error: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
    assert_eq!(
        (error["error"]["kind"].as_str(), out.status.code()),
        (Some("connector_fault"), Some(3))
    );
    let message = error["error"]["message"].as_str().unwrap();
    assert!(
        message
            .contains("(4092 Remote-PIN-KT benötigt aber für diesen Arbeitsplatz nicht definiert)"),
        "{message}"
    );
    let hint = error["error"]["hint"].as_str().unwrap();
    assert!(
        hint.contains("Remote-PIN-KT") && hint.contains("workplaceId"),
        "{hint}"
    );
    let text = String::from_utf8(fake.ti(&args).stderr).unwrap();
    assert!(
        text.contains("4092") && text.contains("Remote-PIN-KT for it"),
        "{text}"
    );
}

/// The card table names each card's terminal and slot, and shortens UUID-shaped values
/// so it fits a terminal; `-v` and JSON keep them whole.
#[test]
fn card_table_shows_the_terminal_and_shortens_long_handles() {
    let fake = Fake::start("card-table");
    let table = |verbose: bool| {
        let mut args = vec![
            "--format",
            "text",
            "connector",
            "-c",
            "praxis",
            "get",
            "cards",
        ];
        if verbose {
            args.insert(0, "-v");
        }
        let out = fake.ti(&args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    let text = table(false);
    assert!(text.contains("TERMINAL"), "{text}");
    assert!(text.contains("CT1 · slot 1"), "{text}");
    assert!(text.contains("card-kt-…0e1f2a3b"), "{text}");
    assert!(!text.contains(KT_HANDLE), "{text}");
    assert!(table(true).contains(KT_HANDLE));

    let (cards, _) = fake.json("connector get cards", &["get", "cards"]);
    let handles: Vec<&str> = cards["cards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["handle"].as_str().unwrap())
        .collect();
    assert!(handles.contains(&KT_HANDLE), "{handles:?}");
}

/// `describe card` says per user PIN whether it must be entered before signing: verified,
/// entry needed with the tries left, or blocked; an SMC-KT has none.
#[test]
fn describe_card_shows_each_pin_status() {
    let fake = Fake::start("pin-status");
    let (smcb, _) = fake.json(
        "connector describe card",
        &["describe", "card", "card-smcb"],
    );
    assert_eq!(
        smcb["pins"],
        serde_json::json!([{"pin": "PIN.SMC", "status": "VERIFIED", "left_tries": null, "error": null}])
    );
    let (hba, _) = fake.json("connector describe card", &["describe", "card", "card-hba"]);
    assert_eq!(
        hba["pins"],
        serde_json::json!([
            {"pin": "PIN.CH", "status": "VERIFIABLE", "left_tries": 3, "error": null},
            {"pin": "PIN.QES", "status": "BLOCKED", "left_tries": 0, "error": null},
        ])
    );
    let (kt, _) = fake.json("connector describe card", &["describe", "card", KT_HANDLE]);
    assert_eq!(kt["pins"], serde_json::json!([]));
    assert!(kt["telematik_id"].is_null(), "an SMC-KT has none");
    assert!(
        smcb["telematik_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "from the C.AUT: {smcb}"
    );

    let out = fake.ti(&[
        "--format",
        "text",
        "connector",
        "-c",
        "praxis",
        "describe",
        "card",
        "card-hba",
    ]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("PIN entry needed · 3 tries left"), "{text}");
    assert!(text.contains("blocked: unblock with the PUK"), "{text}");
    assert!(text.contains("Telematik-ID"), "{text}");
    assert!(text.contains("CT1 · slot 2"), "{text}");
}

/// A card's certificates share holder and Telematik-ID: the table says them once above
/// itself instead of in every row.
#[test]
fn certificates_of_one_holder_name_it_once() {
    let fake = Fake::start("certs-shared");
    let out = fake.ti(&[
        "--format",
        "text",
        "connector",
        "-c",
        "praxis",
        "get",
        "certificates",
        "card-smcb",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Telematik-ID"), "{text}");
    assert!(!text.contains("TELEMATIK-ID"), "no column: {text}");
    assert!(!text.contains("SUBJECT"), "no column: {text}");
    assert!(text.contains("REF"), "{text}");
}

#[test]
fn the_configurations_are_listed_where_they_are_looked_for() {
    let fake = Fake::start("list");
    let list = fake.ti(&["--format", "json", "connector", "config", "list"]);
    assert_eq!(list.status.code(), Some(0));
    let listed: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(listed["configurations"][0]["name"], "praxis");

    let old_name = fake.ti(&["--format", "json", "connector", "configs"]);
    assert_eq!(old_name.status.code(), Some(0));
    assert_eq!(old_name.stdout, list.stdout, "the old name lists the same");

    let help = fake.ti(&["connector", "--help"]);
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        !help.lines().any(|l| l.trim_start().starts_with("configs")),
        "{help}"
    );
    let help = fake.ti(&["connector", "config", "--help"]);
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.lines().any(|l| l.trim_start().starts_with("list")),
        "{help}"
    );
}

#[test]
fn use_without_a_name_lists_and_selects_nothing() {
    let fake = Fake::start("use-list");
    let (listed, code) = fake.json("connector use", &["use"]);
    assert_eq!(code, Some(0));
    assert_eq!(listed["configurations"][0]["name"], "praxis");
    let verbose = |fake: &Fake| fake.ti(&["-v", "--format", "json", "connector", "get", "info"]);
    assert!(
        !String::from_utf8_lossy(&verbose(&fake).stderr).contains("the active selection"),
        "listing selected something"
    );

    let (selected, code) = fake.json("connector use", &["use", "praxis"]);
    assert_eq!(code, Some(0));
    assert_eq!(selected["name"], "praxis");
    assert!(String::from_utf8_lossy(&verbose(&fake).stderr).contains("the active selection"));
}

#[test]
fn the_selection_and_the_cache_are_used() {
    let fake = Fake::start("selection");
    assert_eq!(
        fake.ti(&["connector", "use", "praxis"]).status.code(),
        Some(0)
    );
    let out = fake.ti(&["-v", "--format", "json", "connector", "get", "cards"]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("connector praxis (the active selection)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("expanded from the environment: KON_TEST_PASSWORD"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Basic "),
        "never the authorization header: {stderr}"
    );

    let again = fake.ti(&["-v", "--format", "json", "connector", "get", "cards"]);
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(stderr.contains("service directory from Cache"), "{stderr}");
    assert!(
        !stderr.contains("GET http"),
        "no second directory request: {stderr}"
    );
    let entries = fake.dir.join("cache/v1");
    assert_eq!(std::fs::read_dir(entries).unwrap().count(), 1);
}

#[test]
fn documents_are_signed_verified_encrypted_and_decrypted() {
    let fake = Fake::start("documents");
    let text = fake.dir.join("letter.txt");
    std::fs::write(&text, "ti-connector-client e2e").unwrap();
    let text = path_str(&text);

    let (signed, code) = fake.json("connector sign", &["sign", text, "--card", "card-smcb"]);
    assert_eq!((signed["format"].as_str(), code), (Some("cades"), Some(0)));
    let p7s = format!("{text}.p7s");
    assert!(
        std::fs::metadata(&p7s).unwrap().len() > 1000,
        "the recorded CMS"
    );
    let again = fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "sign",
        text,
        "--card",
        "card-smcb",
    ]);
    assert_eq!(again.status.code(), Some(2), "no overwrite without --force");

    let (verdict, code) = fake.json(
        "connector verify signature",
        &["verify", "signature", text, "--signature", &p7s],
    );
    assert_eq!((verdict["result"].as_str(), code), (Some("VALID"), Some(0)));

    let pdf = fake.dir.join("report.pdf");
    std::fs::write(&pdf, "%PDF-1.4").unwrap();
    let (signed, _) = fake.json(
        "connector sign",
        &["sign", path_str(&pdf), "--card", "card-smcb"],
    );
    assert_eq!(signed["format"], "pades");
    assert_eq!(
        std::fs::read(fake.dir.join("report.signed.pdf")).unwrap(),
        b"%PDF-signed"
    );

    let cert = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ti-pki/tests/pki/ee-arzt.pem"
    );
    let (encrypted, _) = fake.json("connector encrypt", &["encrypt", text, "--to", cert]);
    assert_eq!(encrypted["recipients"][0], "Dr. Arzt TEST-ONLY");
    let p7m = format!("{text}.p7m");
    let out = fake.dir.join("plain.txt");
    let (decrypted, _) = fake.json(
        "connector decrypt",
        &["decrypt", &p7m, "--card", "card-smcb", "-o", path_str(&out)],
    );
    assert_eq!(decrypted["mime_type"], "text/plain");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "ti-connector-client e2e"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "plaintext is the owner's only");
    }
}

/// Whether `text` holds anything shaped like a UUID: 8-4-4-4-12 hex digits.
fn contains_uuid(text: &str) -> bool {
    let b = text.as_bytes();
    b.windows(36).any(|w| {
        w.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
    })
}

/// Where the one user ID of the HBA is kept: below the state directory, by Konnektor
/// name and ICCSN.
fn id_file(fake: &Fake) -> PathBuf {
    fake.dir
        .join("state/telematik/ti/hba-user/praxis/80276001011699910103")
}

impl Fake {
    /// The user IDs of the calls naming `handle` since [`forget_calls`](Self::forget_calls).
    fn user_ids_on(&self, handle: &str) -> Vec<Option<String>> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, body)| body.contains(handle))
            .map(|(_, body)| user_id_of(body).map(str::to_owned))
            .collect()
    }

    /// Every command that names the HBA, each expected to be answered by the Konnektor.
    fn use_the_hba(&self) {
        let text = self.dir.join("use.txt");
        std::fs::write(&text, "x").unwrap();
        let force = ["sign", path_str(&text), "--card", "card-hba", "--force"];
        let commands: [&[&str]; 7] = [
            &["get", "certificates", "card-hba"],
            &["get", "expiration", "card-hba"],
            &["describe", "card", "card-hba"],
            &["verify", "certificate", "card-hba", "C.AUT"],
            &["export", "certificate", "card-hba", "C.AUT"],
            &["change", "pin", "card-hba", "PIN.CH"],
            &force,
        ];
        for command in commands {
            let mut all = vec!["--format", "json", "connector", "-c", "praxis"];
            all.extend_from_slice(command);
            let out = self.ti(&all);
            // `verify certificate` exits 1 for the fake's INVALID, which is an answer too.
            assert!(
                matches!(out.status.code(), Some(0 | 1)),
                "{command:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

/// gemSpec_Kon TAB_KON_514-01: while comfort signature is on, a call under another ID is
/// refused with 4018, so every call on the HBA goes under the comfort ID.
#[test]
fn tab_kon_514_every_call_on_the_hba_uses_its_comfort_id() {
    let fake = Fake::start("one-id");
    fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    let comfort = std::fs::read_to_string(id_file(&fake)).unwrap();

    fake.forget_calls();
    fake.use_the_hba();
    let used = fake.user_ids_on("card-hba");
    assert_ne!(used.len(), 0);
    assert!(
        used.iter().all(|id| id.as_deref() == Some(comfort.trim())),
        "{used:?}"
    );
    let kept: Vec<_> = std::fs::read_dir(id_file(&fake).parent().unwrap())
        .unwrap()
        .collect();
    assert_eq!(kept.len(), 1, "no second ID is made");
    assert!(!fake.dir.join("state/telematik/ti/comfort").exists());
}

/// gemSpec_Kon TAB_KON_510 C16: an HBA session always has a user ID; without one in the
/// .kon `ti` keeps its own, and calls on other cards go on sending none.
#[test]
fn tab_kon_510_c16_without_any_id_the_hba_gets_one_of_its_own() {
    let fake = Fake::start("generated");
    fake.use_the_hba();
    let kept = std::fs::read_to_string(id_file(&fake)).unwrap();
    let used = fake.user_ids_on("card-hba");
    assert_ne!(used.len(), 0);
    assert!(
        used.iter().all(|id| id.as_deref() == Some(kept.trim())),
        "{used:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let file = id_file(&fake);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(file.parent().unwrap()), 0o700);
    }

    fake.forget_calls();
    fake.json(
        "connector get certificates",
        &["get", "certificates", "card-smcb"],
    );
    let used = fake.user_ids_on("card-smcb");
    assert_ne!(used.len(), 0);
    assert!(used.iter().all(Option::is_none), "{used:?}");
}

/// A_20074, A_21528: each activation has a new ID in place of the one before, and the end
/// of a session leaves none of them to be used again.
#[test]
fn a_20074_every_activation_and_deactivation_ends_with_a_new_id() {
    let fake = Fake::start("activate-new");
    let read = || std::fs::read_to_string(id_file(&fake)).unwrap();
    fake.json(
        "connector get certificates",
        &["get", "certificates", "card-hba"],
    );
    let generated = read();

    fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    let first = read();
    assert_ne!(first, generated);
    fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert!(!id_file(&fake).exists());

    fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    let second = read();
    assert_ne!(second, first);
    assert_ne!(second, generated);
    fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);

    fake.forget_calls();
    fake.json(
        "connector get certificates",
        &["get", "certificates", "card-hba"],
    );
    let after = read();
    assert_eq!(
        fake.user_ids_on("card-hba")[0].as_deref(),
        Some(after.trim())
    );
    assert!(![&generated, &first, &second].contains(&&after), "{after}");
}

/// The .kon's userId is kept as the choice of whoever set it, and no ID is generated.
#[test]
fn the_user_id_of_the_kon_is_used_without_a_comfort_id() {
    let fake = Fake::start("kon-user");
    let kon = std::fs::read_to_string(&fake.kon).unwrap();
    let kon = kon.replacen('{', "{\"userId\": \"U1\",", 1);
    std::fs::write(&fake.kon, kon).unwrap();
    fake.use_the_hba();
    let used = fake.user_ids_on("card-hba");
    assert_ne!(used.len(), 0);
    assert!(
        used.iter().all(|id| id.as_deref() == Some("U1")),
        "{used:?}"
    );
    assert!(!id_file(&fake).exists());

    fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    let comfort = std::fs::read_to_string(id_file(&fake)).unwrap();
    fake.forget_calls();
    fake.use_the_hba();
    let used = fake.user_ids_on("card-hba");
    assert!(
        used.iter().all(|id| id.as_deref() == Some(comfort.trim())),
        "the comfort ID goes first: {used:?}"
    );

    fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert!(!id_file(&fake).exists());
    fake.forget_calls();
    fake.use_the_hba();
    let used = fake.user_ids_on("card-hba");
    assert!(
        used.iter().all(|id| id.as_deref() == Some("U1")),
        "back to the .kon's: {used:?}"
    );
}

/// gemSpec_Kon TAB_KON_514-01: a session of another profile or client still ends in
/// 4018; the hint says what to do.
#[test]
fn tab_kon_514_error_4018_says_what_to_do() {
    let fake = Fake::start("hint");
    *fake.raised_for.lock().unwrap() = Some("another-id".into());
    let out = fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "get",
        "certificates",
        "card-hba",
    ]);
    assert_ne!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("comfort deactivate"), "{stderr}");
}

/// Deactivating also ends the use of an ID no comfort session ran under.
#[test]
fn deactivating_removes_the_id_of_the_card() {
    let fake = Fake::start("deactivate-none");
    fake.json(
        "connector get certificates",
        &["get", "certificates", "card-hba"],
    );
    assert!(id_file(&fake).is_file());
    let (report, code) = fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert_eq!(code, Some(0));
    assert!(report["comfort_signature"].is_null(), "{report}");
    assert!(!id_file(&fake).exists());
}

/// The file holds an ID with or without a session, so only the Konnektor can say a signature
/// needed no PIN (GetSignatureMode, SessionInfo).
#[test]
fn only_the_konnektors_session_makes_a_signature_comfort() {
    let fake = Fake::start("sign-truth");
    assert_eq!(
        sign_text(&fake, "a.txt")["comfort"],
        false,
        "a generated ID"
    );
    assert!(id_file(&fake).is_file());

    assert_eq!(activate(&fake).status.code(), Some(0));
    assert_eq!(sign_text(&fake, "b.txt")["comfort"], true);

    *fake.raised_for.lock().unwrap() = None;
    assert!(id_file(&fake).is_file());
    assert_eq!(
        sign_text(&fake, "c.txt")["comfort"],
        false,
        "the session ended"
    );
}

/// `get cards` only knows the connection broke; `config test` names the step.
#[test]
fn a_broken_connection_points_to_the_step_by_step_test() {
    let fake = Fake::start("transport-hint");
    assert_eq!(
        fake.ti(&[
            "connector",
            "-c",
            "praxis",
            "config",
            "set",
            "url=127.0.0.1:9"
        ])
        .status
        .code(),
        Some(0)
    );
    let out = fake.ti(&["connector", "-c", "praxis", "--no-cache", "get", "cards"]);
    assert_ne!(out.status.code(), Some(0));
    assert!(
        stderr_of(&out).contains("connector config test"),
        "{}",
        stderr_of(&out)
    );
}

#[test]
fn comfort_signature_keeps_the_user_id_in_a_private_file() {
    let fake = Fake::start("comfort");

    let (report, _) = fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    assert_eq!(report["session"]["signatures_left"], 249);
    assert!(report.get("user_id_stored").is_none(), "{report}");
    assert!(id_file(&fake).is_file());

    let (signed, _) = {
        let text = fake.dir.join("a.txt");
        std::fs::write(&text, "x").unwrap();
        fake.json(
            "connector sign",
            &["sign", path_str(&text), "--card", "card-hba"],
        )
    };
    assert_eq!(signed["comfort"], true, "the stored session is used");

    let out = fake.ti(&[
        "-vv",
        "connector",
        "-c",
        "praxis",
        "comfort",
        "status",
        "card-hba",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("UserId>***<"), "{stderr}");
    assert!(!contains_uuid(&stderr), "-vv masks every user ID: {stderr}");

    let (report, _) = fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert!(report["comfort_signature"].is_null(), "{report}");
    assert!(!id_file(&fake).exists());
    let (signed, _) = {
        let text = fake.dir.join("b.txt");
        std::fs::write(&text, "x").unwrap();
        fake.json(
            "connector sign",
            &["sign", path_str(&text), "--card", "card-hba"],
        )
    };
    assert_eq!(signed["comfort"], false, "the session is gone");
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn activate(fake: &Fake) -> Output {
    fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "comfort",
        "activate",
        "card-hba",
    ])
}

#[cfg(unix)]
fn deactivate(fake: &Fake) -> Output {
    fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "comfort",
        "deactivate",
        "card-hba",
    ])
}

#[cfg(unix)]
fn comfort_status(fake: &Fake) -> Output {
    fake.ti(&["connector", "-c", "praxis", "comfort", "status", "card-hba"])
}

fn sign_text(fake: &Fake, name: &str) -> Value {
    let text = fake.dir.join(name);
    std::fs::write(&text, "x").unwrap();
    fake.json(
        "connector sign",
        &["sign", path_str(&text), "--card", "card-hba"],
    )
    .0
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg(unix)]
#[test]
fn a_comfort_id_is_private_on_disk() {
    let fake = Fake::start("comfort-private");
    assert_eq!(activate(&fake).status.code(), Some(0));
    let file = id_file(&fake);
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
    assert_eq!(mode(file.parent().unwrap().parent().unwrap()), 0o700);
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(contains_uuid(&text), "{text}");
}

#[cfg(unix)]
#[test]
fn a_group_readable_comfort_file_is_refused() {
    let fake = Fake::start("comfort-wide-file");
    assert_eq!(activate(&fake).status.code(), Some(0));
    set_mode(&id_file(&fake), 0o640);
    std::fs::write(fake.dir.join("a.txt"), "x").unwrap();
    for out in [
        comfort_status(&fake),
        fake.ti(&[
            "connector",
            "-c",
            "praxis",
            "sign",
            "a.txt",
            "--card",
            "card-hba",
        ]),
    ] {
        assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
        let stderr = stderr_of(&out);
        assert!(stderr.contains("chmod 600"), "{stderr}");
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_comfort_file_is_refused() {
    let fake = Fake::start("comfort-symlink");
    assert_eq!(activate(&fake).status.code(), Some(0));
    let file = id_file(&fake);
    let elsewhere = fake.dir.join("elsewhere");
    std::fs::rename(&file, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &file).unwrap();
    let out = comfort_status(&fake);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("symbolic link"),
        "{}",
        stderr_of(&out)
    );
}

/// Sign and status over a comfort file that is refused: state_file_failed, exit 5, and the
/// card not asked.
fn assert_comfort_refused(fake: &Fake, id: Option<&str>) {
    let text = fake.dir.join("refused.txt");
    std::fs::write(&text, "x").unwrap();
    let sign = [
        "--format",
        "json",
        "connector",
        "-c",
        "praxis",
        "sign",
        path_str(&text),
        "--card",
        "card-hba",
    ];
    let status = [
        "--format",
        "json",
        "connector",
        "-c",
        "praxis",
        "comfort",
        "status",
        "card-hba",
    ];
    for args in [&sign[..], &status[..]] {
        fake.forget_calls();
        let out = fake.ti(args);
        assert_eq!(out.status.code(), Some(5), "{args:?}: {}", stderr_of(&out));
        assert!(
            stderr_of(&out).contains("state_file_failed"),
            "{args:?}: {}",
            stderr_of(&out)
        );
        fake.assert_card_not_asked(id);
    }
}

#[test]
fn malformed_comfort_content_is_refused_before_the_card_is_asked() {
    let fake = Fake::start("comfort-malformed");
    assert_eq!(activate(&fake).status.code(), Some(0));
    std::fs::write(id_file(&fake), "not a user id").unwrap();
    assert_comfort_refused(&fake, None);
    assert_eq!(
        std::fs::read_to_string(id_file(&fake)).unwrap(),
        "not a user id",
        "left as it is"
    );
}

/// Sign and status read the ID and send it, so a link planted at the comfort directory or
/// the Konnektor's below it must not hand them an ID someone else chose or can read.
#[cfg(unix)]
#[test]
fn an_id_behind_a_symlinked_comfort_directory_is_never_sent() {
    let fake = Fake::start("comfort-linked");
    assert_eq!(activate(&fake).status.code(), Some(0));
    let file = id_file(&fake);
    let id = std::fs::read_to_string(&file).unwrap();
    let konnektor = file.parent().unwrap().to_owned();
    let root = konnektor.parent().unwrap().to_owned();

    fake.forget_calls();
    assert_eq!(comfort_status(&fake).status.code(), Some(0));
    assert!(
        fake.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(_, body)| body.contains(&id)),
        "the stored ID goes to the Konnektor when nothing is wrong"
    );

    for dir in [&konnektor, &root] {
        let moved = fake.dir.join("moved");
        std::fs::rename(dir, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, dir).unwrap();
        assert_comfort_refused(&fake, Some(&id));
        std::fs::remove_file(dir).unwrap();
        std::fs::rename(&moved, dir).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn a_comfort_directory_open_to_others_is_refused() {
    let fake = Fake::start("comfort-wide-dir");
    assert_eq!(activate(&fake).status.code(), Some(0));
    let konnektor = id_file(&fake).parent().unwrap().to_owned();
    let root = konnektor.parent().unwrap().to_owned();
    for dir in [&konnektor, &root] {
        set_mode(dir, 0o755);
        let (activations, deactivations) = (
            fake.activations.load(Ordering::SeqCst),
            fake.deactivations.load(Ordering::SeqCst),
        );
        for out in [comfort_status(&fake), activate(&fake), deactivate(&fake)] {
            assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
            let stderr = stderr_of(&out);
            assert!(stderr.contains("chmod 700"), "{stderr}");
            assert!(stderr.contains(&dir.display().to_string()), "{stderr}");
        }
        assert_eq!(mode(dir), 0o755, "never changed silently");
        assert!(id_file(&fake).is_file(), "the ID survives");
        assert_eq!(fake.activations.load(Ordering::SeqCst), activations);
        assert_eq!(fake.deactivations.load(Ordering::SeqCst), deactivations);
        set_mode(dir, 0o700);
    }
    assert_eq!(activate(&fake).status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn a_comfort_directory_that_is_a_symlink_is_refused() {
    let fake = Fake::start("comfort-dir-symlink");
    let root = fake.dir.join("state/telematik/ti/hba-user");
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    let elsewhere = fake.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
    let out = activate(&fake);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
    assert_eq!(fake.activations.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);

    let behind = elsewhere.join("praxis");
    std::fs::create_dir(&behind).unwrap();
    set_mode(&behind, 0o700);
    let survivor = behind.join("80276001011699910103");
    std::fs::write(&survivor, "0b9d1d7c-6b1b-4c52-9d0a-0e2b8f3f6a11").unwrap();
    set_mode(&survivor, 0o600);
    let out = deactivate(&fake);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
    assert!(survivor.is_file(), "nothing is deleted through the link");
    assert_eq!(fake.deactivations.load(Ordering::SeqCst), 0);
}

fn files_below(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        found.push(path.clone());
        if path.is_dir() {
            files_below(&path, found);
        }
    }
}

#[test]
fn a_hostile_card_id_stays_in_the_comfort_directory() {
    let fake = Fake::start_with_hba_iccsn("comfort-hostile", Some("../../x"));
    assert_eq!(activate(&fake).status.code(), Some(0));
    let comfort = fake.dir.join("state/telematik/ti/hba-user");
    let mut created = Vec::new();
    files_below(&fake.dir.join("state"), &mut created);
    for path in &created {
        let inside =
            path.starts_with(&comfort) || comfort.starts_with(path) || path.ends_with("telematik");
        assert!(inside, "{} is outside hba-user/", path.display());
    }
    assert!(!fake.dir.join("state/telematik/ti/x").exists());
    assert!(!fake.dir.join("state/x").exists());
    let names: Vec<String> = std::fs::read_dir(comfort.join("praxis"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 1, "{names:?}");
    assert!(
        names[0].len() == 64 && names[0].bytes().all(|b| b.is_ascii_hexdigit()),
        "{names:?}"
    );
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true, "found again");
}

#[test]
fn a_card_without_iccsn_is_kept_by_its_handle() {
    let fake = Fake::start_with_hba_iccsn("comfort-no-iccsn", None);
    assert_eq!(activate(&fake).status.code(), Some(0));
    let file = fake.dir.join("state/telematik/ti/hba-user/praxis/card-hba");
    assert!(file.is_file());
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true);
}

#[test]
fn activate_fails_before_the_card_is_asked_when_state_cannot_be_written() {
    let fake = Fake::start("comfort-unwritable");
    let state = fake.dir.join("state/telematik/ti");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("hba-user"), "in the way").unwrap();
    let out = activate(&fake);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("hba-user"), "{}", stderr_of(&out));
    assert_eq!(
        fake.activations.load(Ordering::SeqCst),
        0,
        "the card was not asked"
    );
}

#[test]
fn profiles_keep_separate_comfort_ids() {
    let fake = Fake::start("comfort-profiles");
    let run = |profile: &str, what: &str| {
        fake.ti(&[
            "--format",
            "json",
            "--profile",
            profile,
            "connector",
            "-c",
            "praxis",
            "comfort",
            what,
            "card-hba",
        ])
    };
    let in_profile = |profile: &str, what: &str| {
        let out = run(profile, what);
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    assert!(in_profile("home", "status")["session"].is_null());
    assert!(!in_profile("work", "activate")["session"].is_null());
    assert!(!in_profile("work", "status")["session"].is_null());
    // GetSignatureMode checks access like any call (TUC_KON_000): another profile's ID is
    // another user's.
    let refused = run("home", "status");
    assert_ne!(refused.status.code(), Some(0));
    assert!(
        stderr_of(&refused).contains("4018"),
        "{}",
        stderr_of(&refused)
    );
    assert!(
        fake.dir
            .join("state/telematik/ti/profiles/work/hba-user/praxis/80276001011699910103")
            .is_file()
    );
    let id_of = |profile: &str| {
        std::fs::read_to_string(fake.dir.join(format!(
            "state/telematik/ti/profiles/{profile}/hba-user/praxis/80276001011699910103"
        )))
        .unwrap()
    };
    assert_ne!(id_of("home"), id_of("work"));
    assert!(!id_file(&fake).exists());
}

#[cfg(unix)]
#[test]
fn a_kept_id_file_is_used_and_deactivating_removes_it() {
    let fake = Fake::start("comfort-legacy");
    let file = id_file(&fake);
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(file.parent().unwrap())
            .unwrap();
    }
    std::fs::write(&file, "0b9d1d7c-6b1b-4c52-9d0a-0e2b8f3f6a11\n").unwrap();
    set_mode(&file, 0o600);
    *fake.raised_for.lock().unwrap() = Some("0b9d1d7c-6b1b-4c52-9d0a-0e2b8f3f6a11".into());
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true);
    let (report, _) = fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert!(report["comfort_signature"].is_null(), "{report}");
    assert!(!file.exists());
}

/// The comfort commands read nothing of the sealed store: content no reader could parse
/// sits at each of its paths, so a reader on any of them fails the command. The trust
/// commands are `tests/schema.rs`'s.
#[test]
fn the_old_store_files_are_not_read_by_the_comfort_commands() {
    let fake = Fake::start("comfort-old-store");
    let old = seed_old_store(
        &fake.dir.join("state"),
        &[&fake.dir.join("cache"), &fake.dir.join("xdg-cache")],
        &fake.dir.join("config"),
    );
    assert_eq!(activate(&fake).status.code(), Some(0));
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true);
    let (report, code) = fake.json("connector comfort", &["comfort", "status", "card-hba"]);
    assert_eq!(code, Some(0), "{report}");
    assert_old_store_untouched(&old);
}

#[test]
fn certificates_are_exported_without_json() {
    let fake = Fake::start("export");
    let out = fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "export",
        "certificate",
        "card-smcb",
        "C.AUT",
    ]);
    let pem = String::from_utf8(out.stdout).unwrap();
    assert!(
        pem.starts_with("-----BEGIN CERTIFICATE-----"),
        "PEM on stdout, also piped: {pem}"
    );
    assert_eq!(pem.matches("BEGIN CERTIFICATE").count(), 1);

    let der = fake.dir.join("aut.der");
    let (report, _) = fake.json(
        "connector export certificate",
        &[
            "export",
            "certificate",
            "card-smcb",
            "c.aut",
            "--der",
            "-o",
            path_str(&der),
        ],
    );
    assert_eq!(report["output"], path_str(&der));
    assert_eq!(std::fs::read(&der).unwrap()[0], 0x30, "DER");

    let (report, _) = fake.json(
        "connector export certificate",
        &["export", "certificate", "card-smcb"],
    );
    assert!(report["output"].is_null());
    assert!(
        report["certificates"][0]["pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );

    let text = fake.dir.join("t.txt");
    std::fs::write(&text, "x").unwrap();
    let (encrypted, _) = fake.json(
        "connector encrypt",
        &["encrypt", path_str(&text), "--to-card", "card-smcb"],
    );
    assert_eq!(encrypted["recipients"][0], "Dr. Arzt TEST-ONLY");
}

/// A proxy from the environment would route the Konnektor's traffic and credentials
/// elsewhere: only `-x` sets one.
#[test]
fn proxy_variables_do_not_apply_to_the_konnektor() {
    let fake = Fake::start("proxy-variables");
    let closed = Path::new("http://127.0.0.1:1");
    let out = fake.ti_with(
        &["connector", "-c", "praxis", "get", "cards"],
        &[
            ("ALL_PROXY", closed),
            ("HTTP_PROXY", closed),
            ("HTTPS_PROXY", closed),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

/// `config show` names where each secret is kept, never its value, and leaves out the
/// user ID, which in a comfort signature session lets anyone sign without a PIN.
#[test]
fn config_show_carries_no_secret() {
    let fake = Fake::start("config-show");
    let kon = std::fs::read_to_string(&fake.kon).unwrap().replace(
        r#""clientSystemId": "C1","#,
        r#""clientSystemId": "C1", "userId": "comfort-user-id","#,
    );
    std::fs::write(
        fake.kon.with_file_name("plain.kon"),
        kon.replace("${KON_TEST_PASSWORD}", "s3cret-pw"),
    )
    .unwrap();
    let (show, code) = fake.json("connector config show", &["config", "show", "plain"]);
    assert_eq!(code, Some(0));
    assert_eq!(show["credentials"]["password"]["stored"], "plain");
    assert_eq!(show["user_id_set"], true);
    let (show, _) = fake.json("connector config show", &["config", "show"]);
    assert_eq!(show["name"], "praxis", "-c is the default");
    assert_eq!(
        show["credentials"]["password"]["variables"][0],
        "KON_TEST_PASSWORD"
    );
    for format in ["json", "text", "markdown"] {
        let out = fake.ti(&["--format", format, "connector", "config", "show", "plain"]);
        let shown = String::from_utf8(out.stdout).unwrap();
        for secret in ["s3cret", "comfort-user-id"] {
            assert!(!shown.contains(secret), "{format}: {secret} in {shown}");
        }
    }
}

/// The service directory is read over https only: the plain-http fake fails the file
/// step, and every step after it is skipped.
#[test]
fn config_test_fails_an_http_url_and_skips_the_rest() {
    let fake = Fake::start("config-test");
    let (report, code) = fake.json("connector config test", &["config", "test"]);
    assert_eq!((report["status"].as_str(), code), (Some("fail"), Some(1)));
    let steps = report["steps"].as_array().unwrap();
    assert_eq!(
        (steps[0]["id"].as_str(), steps[0]["status"].as_str()),
        (Some("file"), Some("fail"))
    );
    assert!(
        steps[0].to_string().contains("is not https"),
        "{}",
        steps[0]
    );
    assert!(steps[1..].iter().all(|s| s["status"] == "skip"), "{report}");
    let text = String::from_utf8(
        fake.ti(&["connector", "-c", "praxis", "config", "test"])
            .stdout,
    )
    .unwrap();
    assert!(text.contains("change url to https://"), "{text}");
}

/// Over TLS with the pinned certificate, every step runs to the cards.
#[test]
fn config_test_runs_every_step_against_a_pinned_konnektor() {
    let fake = Fake::start_tls("config-test-tls");
    let (report, code) = fake.json("connector config test", &["config", "test"]);
    assert_eq!(code, Some(0), "{report}");
    let steps = report["steps"].as_array().unwrap();
    let status = |id: &str| steps.iter().find(|s| s["id"] == id).unwrap()["status"].clone();
    assert_eq!(status("tls"), "ok", "{report}");
    assert_eq!(status("cards"), "ok", "{report}");
    assert!(
        report
            .to_string()
            .contains("matches the pinned certificate")
    );
}

// ---- config new, set, edit, pin ------------------------------------------------------

const TLS_SERVER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server.pem");
const TLS_SERVER_KEY: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/server-key.pem");
const TLS_OTHER: &[u8] = include_bytes!("../../ti-connector-client/tests/tls/other.pem");

fn tls_der(pem: &[u8]) -> Vec<u8> {
    use rustls::pki_types::pem::PemObject as _;
    rustls::pki_types::CertificateDer::from_pem_slice(pem)
        .unwrap()
        .to_vec()
}

fn sha256_hex(der: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A TLS endpoint with the test server certificate that completes handshakes and
/// nothing else: what `config pin` and `config new` fetch the certificate from.
fn tls_server_config() -> std::sync::Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject as _;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(tls_der(TLS_SERVER))],
                rustls::pki_types::PrivateKeyDer::from_pem_slice(TLS_SERVER_KEY).unwrap(),
            )
            .unwrap(),
    )
}

fn tls_konnektor() -> u16 {
    let config = tls_server_config();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).ok()?;
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .ok()?;
                conn.complete_io(&mut socket).ok()?;
                // Take the whole request before closing: a close with the request still
                // unread is a reset, and whether the client saw the reset or the close
                // would depend on timing.
                let (mut request, mut chunk) = (Vec::new(), [0u8; 4096]);
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match std::io::Read::read(&mut conn.reader(), &mut chunk) {
                        Ok(0) => return None,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if conn.complete_io(&mut socket).ok()?.0 == 0 {
                                return None;
                            }
                        }
                        Err(_) => return None,
                    }
                }
                conn.send_close_notify();
                conn.complete_io(&mut socket).ok()?;
                Some(())
            });
        }
    });
    port
}

impl Fake {
    fn url(&self) -> String {
        let kon: Value = serde_json::from_slice(&std::fs::read(&self.kon).unwrap()).unwrap();
        kon["url"].as_str().unwrap().to_owned()
    }

    fn secret_file(&self, name: &str, value: &str) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, format!("{value}\n")).unwrap();
        path
    }

    fn connectors(&self) -> PathBuf {
        self.dir.join("config/telematik/connectors")
    }
}

/// `config new praxis2` from options, its pin from `pin` (`--pin-cert FILE` or
/// `--pin-sha256 HEX`).
fn new_args<'a>(url: &'a str, password: &'a Path, pin: [&'a str; 2]) -> Vec<&'a str> {
    let mut args = vec![
        "--format",
        "json",
        "connector",
        "config",
        "new",
        "praxis2",
        "--url",
        url,
        "--env",
        "ru",
        "--mandant",
        "M1",
        "--client-system",
        "C1",
        "--workplace",
        "W1",
        "--basic",
        "u",
        "--password-path",
        path_str(password),
        // The fake's service directory names the recorded Konnektor's endpoints.
        "--rewrite-endpoints",
    ];
    args.extend(pin);
    args
}

#[cfg(unix)]
fn file_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

impl Fake {
    /// The test server certificate as a file, for --pin-cert.
    fn pin_cert(&self) -> PathBuf {
        let path = self.dir.join("server.pem");
        std::fs::write(&path, TLS_SERVER).unwrap();
        path
    }
}

/// Without a terminal, `config new` takes everything from its options, tests the file
/// before it saves it with mode 0600, and never prints the password.
#[test]
fn config_new_from_options_saves_a_tested_file_only_its_owner_reads() {
    let fake = Fake::start_tls("config-new");
    let password = fake.secret_file("pw", "s3cret-pw");
    let (url, pin) = (fake.url(), fake.pin_cert());
    let args = new_args(&url, &password, ["--pin-cert", path_str(&pin)]);
    let out = fake.ti(&args);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_conforms("connector config new", stdout.as_bytes());
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["saved"], true);
    assert_eq!(report["test"]["steps"][6]["status"], "ok", "{report}");
    assert!(!stdout.contains("s3cret") && !stderr.contains("s3cret"));
    let file = fake.connectors().join("praxis2.kon");
    let kon: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(kon["credentials"]["password"], "s3cret-pw");
    assert_eq!(kon["workplaceId"], "W1");
    #[cfg(unix)]
    assert_eq!(file_mode(&file), 0o600);
    let again = fake.ti(&args);
    assert_eq!(
        again.status.code(),
        Some(2),
        "an existing file needs --force"
    );
}

#[test]
fn config_new_without_a_terminal_names_the_missing_option() {
    let fake = Fake::start_tls("config-new-missing");
    let password = fake.secret_file("pw", "p");
    let (url, pin) = (fake.url(), fake.pin_cert());
    let args: Vec<&str> = new_args(&url, &password, ["--pin-cert", path_str(&pin)])
        .into_iter()
        .filter(|a| !["--mandant", "M1"].contains(a))
        .collect();
    let out = fake.ti(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--mandant is required"));
    assert!(!fake.connectors().join("praxis2.kon").exists());
}

/// An http address is refused everywhere; insecureSkipVerify and credentials of type
/// none for pu.
#[test]
fn config_new_refuses_http_and_what_production_does_not_allow() {
    let fake = Fake::start("config-new-pu");
    let password = fake.secret_file("pw", "p");
    let pin = fake.pin_cert();
    let out = fake.ti(&new_args(
        &fake.url(),
        &password,
        ["--pin-cert", path_str(&pin)],
    ));
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be https"));
    let pu = |args: Vec<&str>| -> Vec<String> {
        args.into_iter()
            .map(|a| {
                if a == "ru" {
                    "pu".to_owned()
                } else {
                    a.to_owned()
                }
            })
            .collect()
    };
    let url = "https://127.0.0.1:1";
    let insecure = pu(new_args(
        url,
        &password,
        ["--insecure-skip-verify", "--no-test"],
    ));
    let credentials = ["--basic", "u", "--password-path", path_str(&password)];
    let mut none: Vec<String> = pu(new_args(url, &password, ["--pin-cert", path_str(&pin)]))
        .into_iter()
        .filter(|a| !credentials.contains(&a.as_str()))
        .collect();
    none.push("--no-auth".into());
    for (args, what) in [(insecure, "insecureSkipVerify"), (none, "type none")] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = fake.ti(&args);
        assert_eq!(out.status.code(), Some(2), "{what}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(what) && stderr.contains("env pu"),
            "{what}: {stderr}"
        );
    }
    assert!(!fake.connectors().join("praxis2.kon").exists());
}

/// A configuration that fails its test is not saved, unless --no-test.
#[test]
fn config_new_saves_nothing_that_fails_its_test() {
    let fake = Fake::start("config-new-fail");
    let password = fake.secret_file("pw", "p");
    let pin = fake.pin_cert();
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("https://127.0.0.1:{closed}");
    let out = fake.ti(&new_args(&url, &password, ["--pin-cert", path_str(&pin)]));
    assert_eq!(out.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["saved"], false);
    assert!(!fake.connectors().join("praxis2.kon").exists());
    let mut args = new_args(&url, &password, ["--pin-cert", path_str(&pin)]);
    args.push("--no-test");
    let out = fake.ti(&args);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<Value>(&out.stdout).unwrap()["test"],
        Value::Null
    );
    assert!(fake.connectors().join("praxis2.kon").exists());
}

/// --pin-sha256 pins the server's certificate only if it is the one named; without a
/// terminal and without a pin option nothing is trusted.
#[test]
fn config_new_pins_the_server_certificate_by_its_sha256() {
    let fake = Fake::start("config-new-pin");
    let password = fake.secret_file("pw", "p");
    let url = format!("https://127.0.0.1:{}", tls_konnektor());
    let wrong = sha256_hex(&tls_der(TLS_OTHER));
    let mut args = new_args(&url, &password, ["--pin-sha256", &wrong]);
    args.push("--no-test");
    let out = fake.ti(&args);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing pinned"));
    let right = sha256_hex(&tls_der(TLS_SERVER))
        .replace(':', "")
        .to_lowercase();
    let mut args = new_args(&url, &password, ["--pin-sha256", &right]);
    args.push("--no-test");
    let out = fake.ti(&args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let kon: Value =
        serde_json::from_slice(&std::fs::read(fake.connectors().join("praxis2.kon")).unwrap())
            .unwrap();
    assert_eq!(kon["trustStore"][0], base64ct_encode(&tls_der(TLS_SERVER)));
    let args = new_args(&url, &password, ["--no-test", "--force"]);
    let out = fake.ti(&args);
    assert_eq!(
        out.status.code(),
        Some(2),
        "without a terminal nothing is trusted unasked"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("--pin-cert or --pin-sha256"));
}

fn base64ct_encode(bytes: &[u8]) -> String {
    use base64ct::Encoding as _;
    base64ct::Base64::encode_string(bytes)
}

#[test]
fn config_set_names_its_configuration_like_the_other_commands() {
    let fake = Fake::start("config-set-c");
    let workplace = |fake: &Fake| {
        let kon: Value = serde_json::from_slice(&std::fs::read(&fake.kon).unwrap()).unwrap();
        kon["workplaceId"].as_str().unwrap().to_owned()
    };
    let before_subcommand = fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "config",
        "set",
        "workplaceId=W2",
    ]);
    assert_eq!(before_subcommand.status.code(), Some(0));
    assert_eq!(workplace(&fake), "W2");

    let after_subcommand = fake.ti(&[
        "connector",
        "config",
        "set",
        "-c",
        "praxis",
        "workplaceId=W3",
    ]);
    assert_eq!(after_subcommand.status.code(), Some(0));
    assert_eq!(workplace(&fake), "W3");

    assert_eq!(
        fake.ti(&["connector", "use", "praxis"]).status.code(),
        Some(0)
    );
    let selected = fake.ti(&["connector", "config", "set", "workplaceId=W4"]);
    assert_eq!(selected.status.code(), Some(0));
    assert_eq!(workplace(&fake), "W4");
    assert!(
        String::from_utf8_lossy(&selected.stdout).contains(path_str(&fake.kon)),
        "it says which file it saved"
    );

    let old_form = fake.ti(&["connector", "config", "set", "praxis", "workplaceId=W5"]);
    assert_eq!(old_form.status.code(), Some(2));
    assert!(
        stderr_of(&old_form).contains("-c"),
        "{}",
        stderr_of(&old_form)
    );
    assert_eq!(workplace(&fake), "W4", "nothing changed");
}

#[test]
fn config_set_changes_members_but_never_secrets() {
    let fake = Fake::start("config-set");
    let (report, code) = fake.json(
        "connector config set",
        &[
            "config",
            "set",
            "workplaceId=W2",
            "url=127.0.0.1:9",
            "userId=",
        ],
    );
    assert_eq!(code, Some(0));
    assert_eq!(
        report["changed"],
        serde_json::json!(["workplaceId", "url", "userId"])
    );
    let kon: Value = serde_json::from_slice(&std::fs::read(&fake.kon).unwrap()).unwrap();
    assert_eq!(
        (kon["workplaceId"].as_str(), kon["url"].as_str()),
        (Some("W2"), Some("https://127.0.0.1:9"))
    );
    let before = std::fs::read(&fake.kon).unwrap();
    for args in [
        &[
            "connector",
            "config",
            "set",
            "-c",
            "praxis",
            "credentials.password=x",
        ][..],
        &[
            "connector",
            "config",
            "set",
            "-c",
            "praxis",
            "env=pu",
            "insecureSkipVerify=true",
        ][..],
    ] {
        let out = fake.ti(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(
            std::fs::read(&fake.kon).unwrap(),
            before,
            "{args:?} left the file as it was"
        );
    }
}

#[test]
fn config_edit_without_a_terminal_changes_only_credentials() {
    let fake = Fake::start("config-edit");
    let out = fake.ti(&["connector", "config", "edit", "praxis"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("an editor needs a terminal"));
    let password = fake.secret_file("pw2", "n3w-pw");
    let (report, code) = fake.json(
        "connector config edit",
        &[
            "config",
            "edit",
            "--basic",
            "u2",
            "--password-path",
            path_str(&password),
        ],
    );
    assert_eq!((code, report["changed"].as_bool()), (Some(0), Some(true)));
    let kon: Value = serde_json::from_slice(&std::fs::read(&fake.kon).unwrap()).unwrap();
    assert_eq!(kon["credentials"]["username"], "u2");
    assert_eq!(kon["mandantId"], "M1", "the rest stays");
}

/// `config pin` replaces the pin by the server's certificate once its SHA-256 matches,
/// and `config test` names the command when the pin no longer matches.
#[test]
fn config_pin_renews_the_pin_that_config_test_reports() {
    let fake = Fake::start("config-pin");
    let port = tls_konnektor();
    let kon = std::fs::read_to_string(&fake.kon)
        .unwrap()
        .replace(&fake.url(), &format!("https://127.0.0.1:{port}"))
        .replace(
            r#""env": "ru","#,
            &format!(
                r#""env": "ru", "trustStore": ["{}"],"#,
                base64ct_encode(&tls_der(TLS_OTHER))
            ),
        );
    std::fs::write(&fake.kon, kon).unwrap();
    let (report, code) = fake.json("connector config test", &["config", "test"]);
    assert_eq!(code, Some(1));
    assert!(
        report.to_string().contains("\"action\":\"renew_pin\""),
        "{report}"
    );
    let text = String::from_utf8(
        fake.ti(&["connector", "-c", "praxis", "config", "test"])
            .stdout,
    )
    .unwrap();
    assert!(text.contains("connector config pin praxis"), "{text}");
    let out = fake.ti(&["connector", "config", "pin", "praxis"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "without a terminal it asks for --pin-sha256"
    );
    let sha = sha256_hex(&tls_der(TLS_SERVER));
    let (report, code) = fake.json(
        "connector config pin",
        &["config", "pin", "--pin-sha256", &sha],
    );
    assert_eq!((code, report["changed"].as_bool()), (Some(0), Some(true)));
    assert_eq!(report["sha256"], sha);
    let kon: Value = serde_json::from_slice(&std::fs::read(&fake.kon).unwrap()).unwrap();
    assert_eq!(
        kon["trustStore"],
        serde_json::json!([base64ct_encode(&tls_der(TLS_SERVER))])
    );
    let (report, _) = fake.json(
        "connector config pin",
        &["config", "pin", "--pin-sha256", &sha],
    );
    assert_eq!(report["changed"], false);
}

/// A Konnektor that cannot be reached is named by its configuration in the error, so the
/// user sees which .kon failed; its address and the calls are -v's.
#[test]
fn an_unreachable_konnektor_is_named_by_its_configuration() {
    let fake = Fake::start("unreachable");
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let kon = std::fs::read_to_string(&fake.kon)
        .unwrap()
        .replace(&fake.url(), &format!("http://127.0.0.1:{closed}"));
    std::fs::write(&fake.kon, kon).unwrap();
    let out = fake.ti(&["connector", "-c", "praxis", "get", "cards"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("Konnektor praxis: "), "{stderr}");
    assert!(
        !stderr.contains(&closed.to_string()),
        "the address is -v's: {stderr}"
    );
}
