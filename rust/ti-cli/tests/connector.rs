//! `tir connector …` against a fake Konnektor on loopback (plain HTTP, the eHEX service
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
            card("card-kt", "SMC-KT", "80276001011699910104", 3, "Terminal"),
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
        let dir = std::env::temp_dir().join(format!("tir-connector-{name}-{}", std::process::id()));
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

    fn tir(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tir"))
            .args(args)
            .current_dir(&self.dir)
            .env_remove("TI_FORMAT")
            .env_remove("TI_CONNECTOR_CONFIG")
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("TI_CACHE_DIR", self.dir.join("cache"))
            .env("XDG_STATE_HOME", self.dir.join("state"))
            .env_remove("TI_COMFORT_USER_ID")
            .env("KON_TEST_PASSWORD", "p")
            .output()
            .unwrap()
    }

    fn json(&self, schema: &str, args: &[&str]) -> (Value, Option<i32>) {
        let mut all = vec!["--format", "json", "connector", "-c", "praxis"];
        all.extend_from_slice(args);
        let out = self.tir(&all);
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
    let out = fake.tir(&[
        "--format",
        "json",
        "connector",
        "-c",
        "praxis",
        "get",
        "certificates",
        "card-kt",
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

    let out = fake.tir(&[
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

    let out = fake.tir(&[
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

#[test]
fn the_selection_and_the_cache_are_used() {
    let fake = Fake::start("selection");
    assert_eq!(
        fake.tir(&["connector", "use", "praxis"]).status.code(),
        Some(0)
    );
    let out = fake.tir(&["-v", "--format", "json", "connector", "get", "cards"]);
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

    let again = fake.tir(&["-v", "--format", "json", "connector", "get", "cards"]);
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(stderr.contains("service directory from Cache"), "{stderr}");
    assert!(
        !stderr.contains("GET http"),
        "no second directory request: {stderr}"
    );
    assert!(fake.dir.join("cache/ti-connector/v1/sds").is_dir());
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
    let again = fake.tir(&[
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

#[test]
fn comfort_signature_keeps_a_random_user_id_per_card() {
    let fake = Fake::start("comfort");
    let stored = fake
        .dir
        .join("state/telematik/ti/comfort/praxis/80276001011699910103");

    let (report, _) = fake.json("connector comfort", &["comfort", "activate", "card-hba"]);
    assert_eq!(report["user_id_stored"], true);
    assert_eq!(report["session"]["signatures_left"], 249);
    let user = std::fs::read_to_string(&stored).unwrap();
    assert!(
        ti_connector_client::ComfortUserId::parse(&user).is_some(),
        "a UUID: {user}"
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

    let out = fake.tir(&[
        "-vv",
        "connector",
        "-c",
        "praxis",
        "comfort",
        "status",
        "card-hba",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(user.trim()),
        "-vv masks the user ID: {stderr}"
    );
    assert!(stderr.contains("UserId>***<"), "{stderr}");

    let (report, _) = fake.json("connector comfort", &["comfort", "deactivate", "card-hba"]);
    assert_eq!(
        (
            report["comfort_signature"].is_null(),
            report["user_id_stored"].as_bool()
        ),
        (true, Some(false))
    );
    assert!(!stored.exists());
}

#[test]
fn certificates_are_exported_without_json() {
    let fake = Fake::start("export");
    let out = fake.tir(&[
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
