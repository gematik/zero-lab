//! Against a real Konnektor, gated by environment variables; without them every test
//! passes without doing anything.
//!
//! - `TI_TEST_KON_PATH`: a `.kon` file. Read-only operations: service directory, cards,
//!   certificates, PIN status, certificate expiry, the Konnektor's certificate check.
//! - `TI_TEST_KON_INTERACTIVE=1` in addition: verifies the PIN of the first SMC-B
//!   (PIN.SMC), or else HBA (PIN.CH), entered at the card terminal, and signs with
//!   ExternalAuthenticate; the signature is checked against the card's C.AUT.
//!
//!   With an SMC-B it then signs a text (CAdES) and, given `TI_TEST_PDFA_PATH`, a PDF/A
//!   (PAdES; Konnektors validate PDF/A conformance) and
//!   verifies each, and encrypts a text for the card's C.ENC and decrypts it.
//! - `TI_TEST_KON_RECORD_DIR`: every exchange is written there, one directory per test,
//!   as material for offline fixtures (bodies only, never credentials).
//!
//! `TI_TEST_KON_PATH=praxis.kon TI_TEST_KON_INTERACTIVE=1 cargo test -p ti-connector-client
//! --features ureq --test e2e -- --nocapture --test-threads 1`

mod support;

use std::time::Duration;

use futures_lite::future::block_on;
use sha2::{Digest, Sha256};
use ti_connector_client::types::{Card, CardType, CertRef, Crypt, PinState};
use ti_connector_client::ureq::UreqTransport;
use ti_connector_client::{
    Connector, Dotkon, Error, PinType, SignatureFormat, SignatureType, Timeouts,
};

use support::Recorder;

type Konnektor = Connector<Recorder<UreqTransport>>;

/// The Konnektor of `TI_TEST_KON_PATH`, recording into `TI_TEST_KON_RECORD_DIR/<test>`.
fn connect(test: &str) -> Option<Konnektor> {
    let path = std::env::var_os("TI_TEST_KON_PATH")?;
    let dotkon = Dotkon::parse(&std::fs::read(&path).expect("TI_TEST_KON_PATH readable"))
        .expect("a valid .kon file");
    let config = ureq::Agent::config_builder().timeout_connect(Some(Duration::from_secs(10)));
    let transport = UreqTransport::new(&dotkon, config).expect("usable credentials");
    let record =
        std::env::var_os("TI_TEST_KON_RECORD_DIR").map(|d| std::path::PathBuf::from(d).join(test));
    let transport = Recorder::new(transport, record);
    let connector = block_on(Connector::connect(
        &dotkon,
        transport,
        Timeouts::RECOMMENDED,
    ))
    .expect("the service directory");
    let p = &connector.directory().product;
    eprintln!(
        "{} {} {} (FW {}) at {}",
        p.vendor_id, p.product_type, p.product_type_version, p.fw_version, dotkon.url
    );
    Some(connector)
}

#[test]
fn read_only_operations() {
    let Some(connector) = connect("read-only") else {
        eprintln!("TI_TEST_KON_PATH not set: skipped");
        return;
    };
    for (service, versions) in ti_connector_client::BINDINGS {
        for version in *versions {
            match connector.directory().resolve(service, &[version]) {
                Ok(b) => eprintln!("  {service} {version} → {} {}", b.version, b.endpoint),
                Err(e) => eprintln!("  {service} {version} → {e}"),
            }
        }
    }
    let cards = block_on(connector.cards().list(&[])).expect("GetCards");
    assert!(!cards.is_empty(), "no card in the Konnektor's terminals");
    for card in &cards {
        eprintln!(
            "card {} {} {}",
            card.card_type,
            card.iccsn.as_deref().unwrap_or("-"),
            card.card_handle
        );
        match block_on(card_checks(&connector, card)) {
            // SMC-KT, KVK and eGK are restricted on the SOAP API (e.g. 4101 Karten-Handle
            // ungültig for GetResourceInformation); only HBA and SMC-B must answer.
            Err(e) if !matches!(card.card_type, CardType::Hba | CardType::SmcB) => {
                eprintln!("  {e}");
            }
            result => result.expect("card operations"),
        }
    }
    // Without a card handle the Konnektor checks every card it knows and fails as a
    // whole on one without the certificate (4132); report, do not require.
    match block_on(connector.certificates().expiration(None, Crypt::Ecc)) {
        Ok(expiry) => eprintln!("all cards: {} certificate expiry dates", expiry.len()),
        Err(e) => eprintln!("all cards: {e}"),
    }
}

/// Resource information, certificates, PIN states, the Konnektor's check of C.AUT, and
/// certificate expiry.
async fn card_checks(connector: &Konnektor, card: &Card) -> Result<(), Error> {
    let again = connector.cards().get(&card.card_handle).await?;
    assert_eq!(again.card_handle, card.card_handle);
    let certificates = connector
        .certificates()
        .read_all(&card.card_handle, card.card_type)
        .await?;
    for c in &certificates {
        eprintln!(
            "  {} {} {} {}",
            c.cert_ref,
            c.crypt,
            c.certificate.subject_cn(),
            c.telematik_id().unwrap_or("-")
        );
    }
    for pin in PinType::for_card(card.card_type) {
        let status = connector.pins().status(&card.card_handle, *pin).await?;
        eprintln!(
            "  {pin}: {:?}, {:?} tries left",
            status.pin_status, status.left_tries
        );
    }
    if let Some(aut) = certificates
        .iter()
        .find(|c| c.cert_ref == CertRef::CAut && c.crypt == Crypt::Ecc)
    {
        let verdict = connector
            .certificates()
            .verify(aut.certificate.der(), None)
            .await?;
        eprintln!(
            "  C.AUT: {:?} {:?}",
            verdict.verification_status.verification_result, verdict.role_list.role
        );
    }
    for e in connector
        .certificates()
        .expiration(Some(&card.card_handle), Crypt::Ecc)
        .await?
    {
        eprintln!("  expires {} {}", e.validity, e.subject_common_name);
    }
    Ok(())
}

#[test]
fn pin_and_external_authenticate() {
    if std::env::var("TI_TEST_KON_INTERACTIVE").as_deref() != Ok("1") {
        eprintln!("TI_TEST_KON_INTERACTIVE not set: skipped");
        return;
    }
    let connector = connect("interactive").expect("TI_TEST_KON_PATH");
    let cards =
        block_on(connector.cards().list(&[CardType::SmcB, CardType::Hba])).expect("GetCards");
    let card = cards.first().expect("an SMC-B or HBA in the Konnektor");
    let (handle, pin) = (&card.card_handle, PinType::for_card(card.card_type)[0]);
    eprintln!("signing with the {} {handle}", card.card_type);

    let status = block_on(connector.pins().status(handle, pin)).expect("GetPinStatus");
    if status.pin_status != Some(PinState::Verified) {
        eprintln!("enter {pin} at the card terminal …");
        let result = block_on(connector.pins().verify(handle, pin)).expect("VerifyPin");
        eprintln!("VerifyPin: {:?}", result.pin_result);
    }

    let certificates = block_on(connector.certificates().read(
        handle,
        Crypt::Ecc,
        &[CertRef::CAut],
    ))
    .expect("C.AUT");
    let aut = &certificates.first().expect("an ECC C.AUT").certificate;
    let message = b"ti-connector-client e2e";
    let raw = block_on(connector.auth().external_authenticate(
        handle,
        &Sha256::digest(message),
        SignatureType::Ecdsa,
    ))
    .expect("ExternalAuthenticate");
    eprintln!("signature: {} bytes", raw.len());

    let algorithm = ti_pki::algorithms::find(
        ti_pki::algorithms::DEFAULT,
        &aut.public_key_alg_id(),
        ti_pki::algorithms::brainpool::ECDSA_BP256R1_SHA256
            .signature_alg_id()
            .as_ref(),
    )
    .expect("a brainpoolP256r1 C.AUT");
    algorithm
        .verify_signature(aut.public_key(), message, &der_signature(&raw))
        .expect("the signature verifies against C.AUT");

    if card.card_type == CardType::SmcB {
        sign_and_verify(&connector, handle);
        encrypt_and_decrypt(&connector, handle);
    }
    let hbas = block_on(connector.cards().list(&[CardType::Hba])).expect("GetCards");
    if let Some(hba) = hbas.first() {
        match block_on(connector.signatures().mode(&hba.card_handle)) {
            Ok(mode) => eprintln!(
                "comfort signature: {:?}, up to {} signatures, {}",
                mode.comfort_signature_status,
                mode.comfort_signature_max,
                mode.comfort_signature_timer
            ),
            Err(e) => eprintln!("comfort signature: {e}"),
        }
    }
}

/// Signs a text (CAdES), and the PDF/A of `TI_TEST_PDFA_PATH` (PAdES) if given, with
/// the SMC-B and verifies each signature.
fn sign_and_verify(connector: &Konnektor, handle: &str) {
    let pdf = std::env::var_os("TI_TEST_PDFA_PATH")
        .map(|p| std::fs::read(p).expect("TI_TEST_PDFA_PATH readable"));
    if pdf.is_none() {
        eprintln!("TI_TEST_PDFA_PATH not set: PAdES skipped");
    }
    let text = b"ti-connector-client e2e".as_slice();
    let cases = [
        (SignatureFormat::Cades, Some(text), "text/plain"),
        (SignatureFormat::Pades, pdf.as_deref(), "application/pdf-a"),
    ];
    let mut failures = Vec::new();
    for (format, document, mime_type) in cases {
        let Some(document) = document else { continue };
        let variant = format.to_string();
        match sign_and_verify_one(connector, handle, format, document, mime_type) {
            Ok(result) => eprintln!("{variant}: signed, verified {result}"),
            Err(e) => {
                eprintln!("{variant}: {e}");
                failures.push(variant);
            }
        }
    }
    assert!(failures.is_empty(), "failed: {failures:?}");
}

/// One signature and its verification; the verification's high-level result.
fn sign_and_verify_one(
    connector: &Konnektor,
    handle: &str,
    format: SignatureFormat,
    document: &[u8],
    mime_type: &str,
) -> Result<String, Error> {
    let signatures = connector.signatures();
    let signed =
        block_on(signatures.sign(handle, format, Some(Crypt::Ecc), &[(document, mime_type)]))?;
    let signed = signed.into_iter().next().expect("one result");
    let verdict = if format == SignatureFormat::Cades {
        block_on(signatures.verify(format, document, mime_type, signed.signature.as_deref()))?
    } else {
        let pdf = signed.signed_document.as_deref().expect("a signed PDF");
        block_on(signatures.verify(format, pdf, mime_type, None))?
    };
    let result = verdict.verification_result.high_level_result;
    assert_ne!(result, "INVALID", "{format}");
    Ok(result)
}

/// Encrypts a text for the SMC-B's own C.ENC and decrypts it with the card.
fn encrypt_and_decrypt(connector: &Konnektor, handle: &str) {
    let enc = block_on(
        connector
            .certificates()
            .read(handle, Crypt::Ecc, &[CertRef::CEnc]),
    )
    .expect("C.ENC");
    let certificate = enc
        .first()
        .expect("an ECC C.ENC")
        .certificate
        .der()
        .to_vec();
    let plain = b"ti-connector-client e2e".as_slice();
    let cms = block_on(
        connector
            .encryption()
            .encrypt(&[&certificate], plain, "text/plain"),
    )
    .expect("EncryptDocument");
    eprintln!("encrypted: {} bytes", cms.len());
    let decrypted = block_on(connector.encryption().decrypt(
        handle,
        Some(Crypt::Ecc),
        &cms,
        "text/plain",
    ))
    .expect("DecryptDocument");
    assert_eq!(decrypted, plain);
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
