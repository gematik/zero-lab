//! The certificate, PIN and authentication facades against scripted responses, shaped
//! like the Konnektor's (namespaces and prefixes as sent by the eHEX Konnektor).

mod support;

use std::time::Duration;

use base64::Engine as _;
use futures_lite::future::block_on;
use ti_connector_client::types::{
    CardType, CertRef, Crypt, PinResult, PinState, StatusResult, VerificationResult,
};
use ti_connector_client::{
    Connector, Dotkon, Error, PinType, ServiceDirectory, SignatureType, Timeouts,
};

use support::{Scripted, ok};

const EHEX_SDS: &[u8] = include_bytes!("fixtures/ehex-connector.sds");
/// An OpenSSL-generated end-entity certificate with an admission (ti-pki's test PKI).
const EE_ARZT: &[u8] = include_bytes!("../../ti-pki/tests/pki/ee-arzt.pem");

const TIMEOUTS: Timeouts = Timeouts {
    short: Duration::from_secs(3),
    long: Duration::from_secs(99),
};

fn connector(transport: &Scripted) -> Connector<&Scripted> {
    let kon = r#"{"url": "https://10.29.128.70", "mandantId": "M", "workplaceId": "W",
        "clientSystemId": "C", "credentials": {"type": "basic", "username": "u", "password": "p"}}"#;
    let dotkon = Dotkon::parse_with(kon.as_bytes(), |_| None).unwrap();
    Connector::new(
        &dotkon,
        transport,
        ServiceDirectory::parse(EHEX_SDS).unwrap(),
        TIMEOUTS,
    )
}

fn envelope(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>{body}</soap:Body></soap:Envelope>"#
    )
}

const STATUS_OK: &str = r#"<CONN:Status xmlns:CONN="http://ws.gematik.de/conn/ConnectorCommon/v5.0"><CONN:Result>OK</CONN:Result></CONN:Status>"#;

fn ee_arzt_der() -> Vec<u8> {
    ti_pki::parse_pem_certificates(EE_ARZT).unwrap()[0]
        .der()
        .to_vec()
}

fn read_card_certificate_response() -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(ee_arzt_der());
    envelope(&format!(
        r#"<CERT:ReadCardCertificateResponse xmlns:CERT="http://ws.gematik.de/conn/CertificateService/v6.0" xmlns:CERTCMN="http://ws.gematik.de/conn/CertificateServiceCommon/v2.0">{STATUS_OK}<CERTCMN:X509DataInfoList>
          <CERTCMN:X509DataInfo><CERTCMN:CertRef>C.AUT</CERTCMN:CertRef><CERTCMN:X509Data>
            <CERTCMN:X509IssuerSerial><CERTCMN:X509IssuerName>CN=Sub CA</CERTCMN:X509IssuerName><CERTCMN:X509SerialNumber>1</CERTCMN:X509SerialNumber></CERTCMN:X509IssuerSerial>
            <CERTCMN:X509SubjectName>CN=Dr. Arzt TEST-ONLY</CERTCMN:X509SubjectName>
            <CERTCMN:X509Certificate>{}
{}</CERTCMN:X509Certificate></CERTCMN:X509Data></CERTCMN:X509DataInfo>
          <CERTCMN:X509DataInfo><CERTCMN:CertRef>C.ENC</CERTCMN:CertRef></CERTCMN:X509DataInfo>
        </CERTCMN:X509DataInfoList></CERT:ReadCardCertificateResponse>"#,
        &b64[..64],
        &b64[64..]
    ))
}

fn fault(code: u32, text: &str) -> String {
    envelope(&format!(
        r#"<soap:Fault><faultcode>soap:Server</faultcode><faultstring>{text}</faultstring><detail><GERROR:Error xmlns:GERROR="http://ws.gematik.de/tel/error/v2.0"><GERROR:MessageID>m</GERROR:MessageID><GERROR:Timestamp>2026-09-27T12:00:00Z</GERROR:Timestamp><GERROR:Trace><GERROR:Code>{code}</GERROR:Code><GERROR:ErrorText>{text}</GERROR:ErrorText></GERROR:Trace></GERROR:Error></detail></soap:Fault>"#
    ))
}

#[test]
fn reads_card_certificates_with_their_admission() {
    let transport = Scripted::new([ok(200, &read_card_certificate_response())]);
    let connector = connector(&transport);
    let certificates = block_on(connector.certificates().read(
        "card-1",
        Crypt::Ecc,
        &[CertRef::CAut, CertRef::CEnc],
    ))
    .unwrap();

    assert_eq!(certificates.len(), 1, "C.ENC has no certificate");
    let aut = &certificates[0];
    assert_eq!((aut.cert_ref, aut.crypt), (CertRef::CAut, Crypt::Ecc));
    assert_eq!(
        aut.certificate.der(),
        ee_arzt_der(),
        "line breaks in base64 are fine"
    );
    assert_eq!(aut.telematik_id(), Some("80276001081234567890"));

    let seen = transport.seen.borrow();
    assert_eq!(
        seen[0].url,
        "https://10.29.128.70:443/ws/CertificateService"
    );
    assert_eq!(seen[0].timeout, TIMEOUTS.short);
    for part in [
        "<certificateservice602:CertRef>C.AUT</certificateservice602:CertRef>",
        "<certificateservice602:CertRef>C.ENC</certificateservice602:CertRef>",
        "<certificateservice602:Crypt>ECC</certificateservice602:Crypt>",
        "<connectorcommon50:CardHandle>card-1</connectorcommon50:CardHandle>",
    ] {
        assert!(seen[0].body.contains(part), "{part} in {}", seen[0].body);
    }
}

#[test]
fn read_all_tolerates_cards_without_rsa_keys() {
    let transport = Scripted::new([
        ok(200, &read_card_certificate_response()),
        ok(500, &fault(4002, "Kartenobjekt nicht vorhanden")),
    ]);
    let smcb = connector(&transport);
    let certificates = block_on(smcb.certificates().read_all("card-1", CardType::SmcB)).unwrap();
    assert_eq!(certificates.len(), 1);
    let seen = transport.seen.borrow();
    assert!(seen[1].body.contains(">RSA</certificateservice602:Crypt>"));
    assert!(
        seen[1]
            .body
            .contains(">C.SIG</certificateservice602:CertRef>")
    );

    drop(seen);
    let transport = Scripted::new([]);
    let egk = connector(&transport);
    let none = block_on(egk.certificates().read_all("egk", CardType::Egk)).unwrap();
    assert!(none.is_empty(), "an eGK has no certificates to read");
    assert!(transport.seen.borrow().is_empty());
}

#[test]
fn certificate_expiration_and_verification() {
    let expiration = envelope(&format!(
        r#"<CERT:CheckCertificateExpirationResponse xmlns:CERT="http://ws.gematik.de/conn/CertificateService/v6.0">{STATUS_OK}
          <CERT:CertificateExpiration><CERT:CtID>CT1</CERT:CtID><CERT:CardHandle>card-1</CERT:CardHandle><CERT:ICCSN>80276001</CERT:ICCSN>
            <CERT:subject_commonName>Praxis</CERT:subject_commonName><CERT:serialNumber>42</CERT:serialNumber><CERT:validity>2029-11-06</CERT:validity></CERT:CertificateExpiration>
        </CERT:CheckCertificateExpirationResponse>"#
    ));
    let verification = envelope(&format!(
        r#"<CERT:VerifyCertificateResponse xmlns:CERT="http://ws.gematik.de/conn/CertificateService/v6.0">{STATUS_OK}
          <CERT:VerificationStatus><CERT:VerificationResult>VALID</CERT:VerificationResult></CERT:VerificationStatus>
          <CERT:RoleList><CERT:Role>1.2.276.0.76.4.50</CERT:Role></CERT:RoleList></CERT:VerifyCertificateResponse>"#
    ));
    let transport = Scripted::new([ok(200, &expiration), ok(200, &verification)]);
    let connector = connector(&transport);

    let expiry = block_on(
        connector
            .certificates()
            .expiration(Some("card-1"), Crypt::Ecc),
    )
    .unwrap();
    assert_eq!(
        (&*expiry[0].subject_common_name, &*expiry[0].validity),
        ("Praxis", "2029-11-06")
    );
    let verdict = block_on(connector.certificates().verify(
        &ee_arzt_der(),
        Some(ti_types::Timestamp::parse_rfc3339("2026-01-01T00:00:00Z").unwrap()),
    ))
    .unwrap();
    assert_eq!(
        verdict.verification_status.verification_result,
        VerificationResult::Valid
    );
    assert_eq!(verdict.role_list.role, ["1.2.276.0.76.4.50"]);

    let seen = transport.seen.borrow();
    assert_eq!(seen[1].timeout, TIMEOUTS.long, "online revocation check");
    assert!(seen[1].body.contains(
        "<certificateservice602:VerificationTime>2026-01-01T00:00:00Z</certificateservice602:VerificationTime>"
    ));
}

#[test]
fn pin_status_verify_and_change() {
    let status = envelope(&format!(
        r#"<CARD:GetPinStatusResponse xmlns:CARD="http://ws.gematik.de/conn/CardService/v8.1">{STATUS_OK}<CARD:PinStatus>VERIFIABLE</CARD:PinStatus><CARD:LeftTries>3</CARD:LeftTries></CARD:GetPinStatusResponse>"#
    ));
    let verified = envelope(&format!(
        r#"<CARD:VerifyPinResponse xmlns:CARD="http://ws.gematik.de/conn/CardService/v8.1" xmlns:CARDCMN="http://ws.gematik.de/conn/CardServiceCommon/v2.0">{STATUS_OK}<CARDCMN:PinResult>REJECTED</CARDCMN:PinResult><CARDCMN:LeftTries>2</CARDCMN:LeftTries></CARD:VerifyPinResponse>"#
    ));
    let transport = Scripted::new([
        ok(200, &status),
        ok(200, &verified),
        ok(500, &fault(4065, "Timeout bei der PIN-Eingabe")),
    ]);
    let connector = connector(&transport);

    let status = block_on(connector.pins().status("card-1", PinType::Smc)).unwrap();
    assert_eq!(
        (status.status.result, status.pin_status, status.left_tries),
        (StatusResult::Ok, Some(PinState::Verifiable), Some(3))
    );
    let verified = block_on(connector.pins().verify("card-1", PinType::Smc)).unwrap();
    assert_eq!(
        (verified.pin_result, verified.left_tries),
        (PinResult::Rejected, Some(2))
    );
    let Err(Error::Fault(fault)) = block_on(connector.pins().change("card-1", PinType::Ch)) else {
        panic!("a fault");
    };
    assert_eq!(fault.trace[0].code, Some(4065));

    let seen = transport.seen.borrow();
    assert_eq!(
        seen.iter().map(|s| s.timeout).collect::<Vec<_>>(),
        [TIMEOUTS.short, TIMEOUTS.long, TIMEOUTS.long]
    );
    assert_eq!(
        seen[0].url, "https://10.29.128.70:443/ws/CardService",
        "8.1.2, not the advertised 8.2.1"
    );
    assert_eq!(
        seen[1].soap_action.as_deref(),
        Some("http://ws.gematik.de/conn/CardService/v8.1#VerifyPin")
    );
    assert!(
        seen[1]
            .body
            .contains(">PIN.SMC</cardservicecommon20:PinTyp>")
    );
    assert!(
        seen[2]
            .body
            .contains(">PIN.CH</cardservicecommon20:PinTyp>")
    );
    assert_eq!("pin.qes".parse::<PinType>(), Ok(PinType::Qes));
    assert_eq!(PinType::for_card(CardType::HsmB), [PinType::Smc]);
}

#[test]
fn external_authenticate_returns_raw_signatures() {
    let der = [
        [0x30, 0x44, 0x02, 0x20].as_slice(),
        &[0x11; 32],
        &[0x02, 0x20],
        &[0x22; 32],
    ]
    .concat();
    let response = envelope(&format!(
        r#"<SIG:ExternalAuthenticateResponse xmlns:SIG="http://ws.gematik.de/conn/SignatureService/v7.4" xmlns:dss="urn:oasis:names:tc:dss:1.0:core:schema">{STATUS_OK}<dss:SignatureObject><dss:Base64Signature Type="urn:bsi:tr:03111:ecdsa">{}</dss:Base64Signature></dss:SignatureObject></SIG:ExternalAuthenticateResponse>"#,
        base64::engine::general_purpose::STANDARD.encode(&der)
    ));
    let transport = Scripted::new([ok(200, &response)]);
    let connector = connector(&transport);
    let hash = [0xab; 32];
    let signature = block_on(connector.auth().external_authenticate(
        "card-1",
        &hash,
        SignatureType::Ecdsa,
    ))
    .unwrap();
    assert_eq!(signature, [[0x11; 32], [0x22; 32]].concat());

    let seen = transport.seen.borrow();
    assert_eq!(
        (&*seen[0].url, seen[0].timeout),
        (
            "https://10.29.128.70:443/ws/AuthSignatureService",
            TIMEOUTS.long
        )
    );
    let hash_b64 = base64::engine::general_purpose::STANDARD.encode(hash);
    for part in [
        "<dss10core:SignatureType>urn:bsi:tr:03111:ecdsa</dss10core:SignatureType>",
        &format!(
            r#"<dss10core:Base64Data MimeType="application/octet-stream">{hash_b64}</dss10core:Base64Data>"#
        ),
    ] {
        assert!(seen[0].body.contains(part), "{part} in {}", seen[0].body);
    }
}
