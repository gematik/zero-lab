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
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

use support::assert_conforms;

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
    if operation == "ActivateComfortSignature" {
        behavior.activations.fetch_add(1, Ordering::SeqCst);
    }
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
}

impl Behavior {
    fn standard() -> Self {
        Behavior {
            hba_iccsn: Some("80276001011699910103".into()),
            activations: Arc::default(),
        }
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
    let (status, response) = answer(&path, &action, &String::from_utf8_lossy(&body), behavior);
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
        let activations = behavior.activations.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let behavior = behavior.clone();
                std::thread::spawn(move || handle(stream, &behavior));
            }
        });
        Fake::with_kon(name, &format!("http://127.0.0.1:{port}"), "", activations)
    }

    /// Over TLS with ti-connector-client's test server certificate, pinned in the
    /// `.kon` file.
    fn start_tls(name: &str) -> Self {
        let config = tls_server_config();
        let behavior = Behavior::standard();
        let activations = behavior.activations.clone();
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
        Fake::with_kon(
            name,
            &format!("https://127.0.0.1:{port}"),
            &pin,
            activations,
        )
    }

    fn with_kon(name: &str, url: &str, extra: &str, activations: Arc<AtomicUsize>) -> Self {
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
            activations,
        }
    }

    fn ti(&self, args: &[&str]) -> Output {
        self.ti_with(args, &[])
    }

    fn ti_with(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ti"));
        cmd.args(args)
            .current_dir(&self.dir)
            .env_remove("TI_FORMAT")
            .env_remove("TI_CONNECTOR_CONFIG")
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("TI_CACHE_DIR", self.dir.join("cache"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env_remove("TI_PROFILE")
            .env_remove("TI_STATE_DIR")
            .env_remove("TI_STORE_KEK_PATH")
            .env_remove("TI_STORE_BACKEND")
            .env_remove("TI_COMFORT_USER_ID")
            .env("KON_TEST_PASSWORD", "p")
            .env_remove("TI_STORE_TRACE");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }

    /// A `ti` command other than `connector`, as JSON checked against its schema.
    fn store_json(
        &self,
        schema: &str,
        args: &[&str],
        env: &[(&str, &Path)],
    ) -> (Value, Option<i32>) {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(args);
        let out = self.ti_with(&all, env);
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

    let (configs, _) = fake.json("connector configs", &["configs"]);
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

/// Where the comfort ID of the HBA is kept: below the state directory, by Konnektor
/// name and ICCSN.
fn comfort_file(fake: &Fake) -> PathBuf {
    fake.dir
        .join("state/telematik/ti/comfort/praxis/80276001011699910103")
}

#[test]
fn comfort_signature_keeps_the_user_id_in_a_private_file() {
    let fake = Fake::start("comfort");

    let (report, _) = fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    assert_eq!(report["user_id_stored"], true);
    assert_eq!(report["session"]["signatures_left"], 249);
    assert!(comfort_file(&fake).is_file());

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
    assert_eq!(
        (
            report["comfort_signature"].is_null(),
            report["user_id_stored"].as_bool()
        ),
        (true, Some(false))
    );
    let (signed, _) = {
        let text = fake.dir.join("b.txt");
        std::fs::write(&text, "x").unwrap();
        fake.json(
            "connector sign",
            &["sign", path_str(&text), "--card", "card-hba"],
        )
    };
    assert_eq!(signed["comfort"], false, "the ID is gone");
}

/// A Konnektor fake whose default profile has a keyring and one sealed record, put there
/// the way the store's interoperability driver does: the comfort ID of the HBA, under
/// this id. Activation no longer writes sealed records, and the store commands under
/// test still read them.
fn fake_with_comfort(name: &str) -> (Fake, &'static str) {
    let fake = Fake::start(name);
    assert_eq!(fake.ti(&["profile", "create"]).status.code(), Some(0));
    let id = "praxis/80276001011699910103";
    let driver = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("examples/store-interop");
    let out = Command::new(driver)
        .args([
            "put",
            "comfort",
            id,
            "0b9d1d7c-6b1b-4c52-9d0a-0e2b8f3f6a11",
            "konnektor=praxis",
        ])
        .env("XDG_STATE_HOME", fake.dir.join("state"))
        .env("XDG_CONFIG_HOME", fake.dir.join("config"))
        .env("TI_CACHE_DIR", fake.dir.join("cache"))
        .env_remove("TI_PROFILE")
        .env_remove("TI_STATE_DIR")
        .env_remove("TI_STORE_KEK_PATH")
        .env_remove("TI_STORE_BACKEND")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (fake, id)
}

/// STORE-124, STORE-127, STORE-123 on a sealed record: ls shows its header and never its
/// id or content, show reveals the content only on request, rotate keeps the kids live
/// records use, doctor --deep opens it.
#[test]
fn store_commands_list_show_and_rotate_sealed_records() {
    let (fake, id) = fake_with_comfort("store-ls");
    let none: &[(&str, &Path)] = &[];

    let (ls, _) = fake.store_json("store ls", &["store", "ls"], none);
    let records = ls["records"].as_array().unwrap();
    let comfort: Vec<&Value> = records
        .iter()
        .filter(|r| r["namespace"] == "comfort")
        .collect();
    assert_eq!(comfort.len(), 1);
    assert_eq!(comfort[0]["fields"], serde_json::json!(["konnektor"]));
    assert_eq!(comfort[0]["payload_bytes"], 36, "a UUID");
    let first_kid = comfort[0]["kid"].as_str().unwrap().to_owned();
    let listing = String::from_utf8_lossy(&fake.ti(&["store", "ls"]).stdout).into_owned();
    assert!(
        !listing.contains("80276001011699910103"),
        "no ids: {listing}"
    );
    assert!(!contains_uuid(&listing), "no contents: {listing}");

    let (shown, _) = fake.store_json("store show", &["store", "show", "comfort", id], none);
    assert!(shown["payload"].is_null());
    let (revealed, _) = fake.store_json(
        "store show",
        &["store", "show", "comfort", id, "--reveal"],
        none,
    );
    assert_eq!(revealed["payload_encoding"], "utf-8");
    assert!(contains_uuid(revealed["payload"].as_str().unwrap()));

    let (rotated, _) = fake.store_json("profile rotate", &["profile", "rotate"], none);
    assert_eq!(rotated["kids"], 2, "the first kid seals the comfort ID");
    let (rotated, _) = fake.store_json("profile rotate", &["profile", "rotate"], none);
    assert_eq!(rotated["kids"], 2);
    assert_eq!(
        rotated["removed_kids"].as_array().unwrap().len(),
        1,
        "unused"
    );
    let (ls, _) = fake.store_json("store ls", &["store", "ls", "comfort"], none);
    assert_eq!(ls["records"][0]["kid"], first_kid.as_str(), "not rewritten");

    let (doctor, code) = fake.store_json("store doctor", &["store", "doctor", "--deep"], none);
    assert_eq!((code, doctor["status"].as_str()), (Some(0), Some("ok")));
}

/// STORE-127, STORE-123, STORE-124 to STORE-126: rewrap moves the keyring to another key
/// file and leaves the records, doctor --deep finds a tampered record, rm and purge
/// remove records; cleanup and migrate report.
#[test]
fn store_commands_rewrap_check_and_remove_sealed_records() {
    let (fake, id) = fake_with_comfort("store-rm");
    let none: &[(&str, &Path)] = &[];
    // a new key file: the old one no longer opens the keyring
    let new_kek = fake.dir.join("new.kek");
    std::fs::write(&new_kek, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&new_kek, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (rewrapped, _) = fake.store_json(
        "profile rewrap",
        &["profile", "rewrap", "--kek-file", path_str(&new_kek)],
        none,
    );
    assert_eq!(rewrapped["kek_path_to_set"], path_str(&new_kek));
    let (_, code) = fake.store_json("store doctor", &["store", "doctor"], none);
    assert_eq!(code, Some(1), "the old key file fails");
    let with_new: &[(&str, &Path)] = &[("TI_STORE_KEK_PATH", &new_kek)];
    let (revealed, _) = fake.store_json(
        "store show",
        &["store", "show", "comfort", id, "--reveal"],
        with_new,
    );
    assert!(
        contains_uuid(revealed["payload"].as_str().unwrap()),
        "records untouched"
    );

    // a record altered on disk does not open
    let state = fake.dir.join("state/telematik/profiles/default/state.db");
    let db = rusqlite::Connection::open(&state).unwrap();
    let value: Vec<u8> = db
        .query_row("SELECT value FROM records WHERE ns = 'comfort'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut tampered = value.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    db.execute(
        "UPDATE records SET value = ?1 WHERE ns = 'comfort'",
        [&tampered],
    )
    .unwrap();
    drop(db);
    let (doctor, code) = fake.store_json("store doctor", &["store", "doctor", "--deep"], with_new);
    assert_eq!(code, Some(1));
    let check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "records_open")
        .unwrap();
    assert!(
        check["detail"].as_str().unwrap().contains("auth_failed 1"),
        "{check}"
    );

    let (removed, _) = fake.store_json("store rm", &["store", "rm", "comfort", id], with_new);
    assert_eq!(
        removed["removed"], 1,
        "a record that does not open is still removed"
    );
    let (removed, _) = fake.store_json("store rm", &["store", "rm", "comfort", id], with_new);
    assert_eq!(removed["removed"], 0);

    let refused = fake.ti(&["store", "purge", "connector.sds"]);
    assert_eq!(refused.status.code(), Some(2));
    let (purged, _) = fake.store_json(
        "store purge",
        &["store", "purge", "connector.sds", "--yes"],
        none,
    );
    assert_eq!(
        purged["removed"], 0,
        "the service directory is a cache file now, not a record"
    );
    let unknown = fake.ti(&["store", "purge", "nope", "--yes"]);
    assert_eq!(unknown.status.code(), Some(2));

    let (cleaned, _) = fake.store_json("store cleanup", &["store", "cleanup"], none);
    assert_eq!(cleaned["databases"].as_array().unwrap().len(), 2);
    let (migrated, _) = fake.store_json("store migrate", &["store", "migrate", "--dry-run"], none);
    assert_eq!(migrated["databases"][0]["outcome"], "up to date");
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
    let file = comfort_file(&fake);
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
    set_mode(&comfort_file(&fake), 0o640);
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
    let file = comfort_file(&fake);
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

#[cfg(unix)]
#[test]
fn a_comfort_directory_open_to_others_is_refused() {
    let fake = Fake::start("comfort-wide-dir");
    assert_eq!(activate(&fake).status.code(), Some(0));
    let konnektor = comfort_file(&fake).parent().unwrap().to_owned();
    let root = konnektor.parent().unwrap().to_owned();
    for dir in [&konnektor, &root] {
        set_mode(dir, 0o755);
        for out in [comfort_status(&fake), activate(&fake)] {
            assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
            let stderr = stderr_of(&out);
            assert!(stderr.contains("chmod 700"), "{stderr}");
            assert!(stderr.contains(&dir.display().to_string()), "{stderr}");
        }
        assert_eq!(mode(dir), 0o755, "never changed silently");
        set_mode(dir, 0o700);
    }
    assert_eq!(activate(&fake).status.code(), Some(0));
}

#[test]
fn a_comfort_directory_that_is_a_symlink_is_refused() {
    let fake = Fake::start("comfort-dir-symlink");
    let root = fake.dir.join("state/telematik/ti/comfort");
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    let elsewhere = fake.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
        let out = activate(&fake);
        assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
        assert_eq!(fake.activations.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }
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
    let comfort = fake.dir.join("state/telematik/ti/comfort");
    let mut created = Vec::new();
    files_below(&fake.dir.join("state"), &mut created);
    for path in &created {
        let inside =
            path.starts_with(&comfort) || comfort.starts_with(path) || path.ends_with("telematik");
        assert!(inside, "{} is outside comfort/", path.display());
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
    let file = fake.dir.join("state/telematik/ti/comfort/praxis/card-hba");
    assert!(file.is_file());
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true);
}

#[test]
fn activate_fails_before_the_card_is_asked_when_state_cannot_be_written() {
    let fake = Fake::start("comfort-unwritable");
    let state = fake.dir.join("state/telematik/ti");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("comfort"), "in the way").unwrap();
    let out = activate(&fake);
    assert_eq!(out.status.code(), Some(5), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("comfort"), "{}", stderr_of(&out));
    assert_eq!(
        fake.activations.load(Ordering::SeqCst),
        0,
        "the card was not asked"
    );
}

#[test]
fn profiles_keep_separate_comfort_ids() {
    let fake = Fake::start("comfort-profiles");
    let in_profile = |profile: &str, what: &str| {
        let out = fake.ti(&[
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
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    assert_eq!(in_profile("work", "activate")["user_id_stored"], true);
    assert_eq!(in_profile("work", "status")["user_id_stored"], true);
    assert_eq!(in_profile("home", "status")["user_id_stored"], false);
    assert!(
        fake.dir
            .join("state/telematik/ti/profiles/work/comfort/praxis/80276001011699910103")
            .is_file()
    );
    assert!(!comfort_file(&fake).exists());
}

#[cfg(unix)]
#[test]
fn a_comfort_id_file_from_an_earlier_version_is_used() {
    let fake = Fake::start("comfort-legacy");
    let file = comfort_file(&fake);
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
    assert_eq!(sign_text(&fake, "a.txt")["comfort"], true);
    let (report, _) = fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert_eq!(report["user_id_stored"], false);
    assert!(!file.exists());
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
fn config_set_changes_members_but_never_secrets() {
    let fake = Fake::start("config-set");
    let (report, code) = fake.json(
        "connector config set",
        &[
            "config",
            "set",
            "praxis",
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
            "praxis",
            "credentials.password=x",
        ][..],
        &[
            "connector",
            "config",
            "set",
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
