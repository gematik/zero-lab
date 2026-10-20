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
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// The fake's cards; GetCards filters by the card type in the request, if any.
fn cards(body: &str) -> String {
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
        (
            "HBA",
            card(
                "card-hba",
                "HBA",
                "80276001011699910103",
                2,
                "Dr. Arzt TEST-ONLY",
            ),
        ),
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
fn answer(path: &str, action: &str, body: &str) -> (u16, String) {
    if path == "/connector.sds" {
        return (200, SDS.to_owned());
    }
    let operation = action
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .trim_matches('"');
    let cards = cards(body);
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

fn handle(stream: TcpStream) -> Option<()> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
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
    let (status, response) = answer(&path, &action, &String::from_utf8_lossy(&body));
    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .ok()
}

/// A fake Konnektor serving until the test process ends, and a `.kon` file for it.
struct Fake {
    dir: PathBuf,
    kon: PathBuf,
}

impl Fake {
    fn start(name: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || handle(stream));
            }
        });
        let dir = std::env::temp_dir().join(format!("ti-connector-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config/telematik/connectors")).unwrap();
        let kon = dir.join("config/telematik/connectors/praxis.kon");
        std::fs::write(
            &kon,
            format!(
                r#"{{"url": "http://127.0.0.1:{port}", "rewriteServiceEndpoints": true,
                    "mandantId": "M1", "workplaceId": "W1", "clientSystemId": "C1", "env": "ru",
                    "credentials": {{"type": "basic", "username": "u", "password": "${{KON_TEST_PASSWORD}}"}}}}"#
            ),
        )
        .unwrap();
        Fake { dir, kon }
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
    assert!(fake.dir.join("cache/profiles/default/cache.db").is_file());
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

/// The comfort ID of a card before the store, where earlier versions kept it.
fn legacy_comfort_file(fake: &Fake) -> PathBuf {
    fake.dir
        .join("state/telematik/ti/comfort/praxis/80276001011699910103")
}

#[test]
fn comfort_signature_needs_a_keyring_and_keeps_the_user_id_sealed() {
    let fake = Fake::start("comfort");

    // STORE-023: without a keyring the ID would have nowhere to go, so the card is not
    // asked at all
    let out = fake.ti(&[
        "connector",
        "-c",
        "praxis",
        "comfort",
        "activate",
        "card-hba",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no_keyring"), "{stderr}");
    assert!(stderr.contains("ti profile create"), "{stderr}");

    assert_eq!(fake.ti(&["profile", "create"]).status.code(), Some(0));
    let (report, _) = fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    assert_eq!(report["user_id_stored"], true);
    assert_eq!(report["session"]["signatures_left"], 249);
    assert!(!legacy_comfort_file(&fake).exists());
    assert!(
        fake.dir
            .join("state/telematik/profiles/default/state.db")
            .is_file()
    );

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

/// A Konnektor fake whose default profile has a keyring and one sealed record: the
/// comfort ID of the HBA, under this id.
fn fake_with_comfort(name: &str) -> (Fake, &'static str) {
    let fake = Fake::start(name);
    assert_eq!(fake.ti(&["profile", "create"]).status.code(), Some(0));
    fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    (fake, "praxis/80276001011699910103")
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
    assert_eq!(purged["removed"], 1, "the service directory");
    let unknown = fake.ti(&["store", "purge", "nope", "--yes"]);
    assert_eq!(unknown.status.code(), Some(2));

    let (cleaned, _) = fake.store_json("store cleanup", &["store", "cleanup"], none);
    assert_eq!(cleaned["databases"].as_array().unwrap().len(), 2);
    let (migrated, _) = fake.store_json("store migrate", &["store", "migrate", "--dry-run"], none);
    assert_eq!(migrated["databases"][0]["outcome"], "up to date");
}

#[test]
fn comfort_ids_of_earlier_versions_move_into_the_store() {
    let fake = Fake::start("comfort-legacy");
    let legacy = legacy_comfort_file(&fake);
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, "0b9d1d7c-6b1b-4c52-9d0a-0e2b8f3f6a11\n").unwrap();
    let sign = |name: &str| {
        let text = fake.dir.join(name);
        std::fs::write(&text, "x").unwrap();
        fake.json(
            "connector sign",
            &["sign", path_str(&text), "--card", "card-hba"],
        )
        .0
    };

    // without a keyring the file is read, never written or removed
    assert_eq!(sign("a.txt")["comfort"], true);
    assert!(legacy.exists());

    assert_eq!(fake.ti(&["profile", "create"]).status.code(), Some(0));
    assert_eq!(sign("b.txt")["comfort"], true);
    assert!(!legacy.exists(), "moved into the sealed store");
    assert_eq!(sign("c.txt")["comfort"], true, "and read from there");
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
