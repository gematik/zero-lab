//! TSLSIG-010 – 023 (XML side) against the published TSLs in
//! `spec/tsl-xmldsig/testdata/tsl/real`, and against variations of one of them that each
//! break one rule.

use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use bp256::BrainpoolP256r1;
use ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use ti_xmldsig::{Document, ErrorKind, Limits, SignedTsl};
use x509_cert::Certificate;
use x509_cert::der::Decode;

fn real() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/tsl-xmldsig/testdata/tsl/real")
}

fn tsl() -> String {
    std::fs::read_to_string(real().join("pu-10334.xml")).unwrap()
}

fn verify(xml: &str) -> Result<SignedTsl, ti_xmldsig::Error> {
    Document::parse(xml.as_bytes(), &Limits::TSL)?.verify_tsl_signature()
}

/// `xml` with `from` replaced by `to` exactly once.
fn edit(xml: &str, from: &str, to: &str) -> String {
    assert_eq!(xml.matches(from).count(), 1, "{from}");
    xml.replacen(from, to, 1)
}

/// The text between `start` and the following `end`.
fn between<'a>(xml: &'a str, start: &str, end: &str) -> &'a str {
    let from = xml.find(start).unwrap() + start.len();
    let len = xml[from..].find(end).unwrap();
    &xml[from..from + len]
}

#[track_caller]
fn rejected(xml: &str, rule: &str) {
    rejected_as(xml, rule, ErrorKind::Signature);
}

#[track_caller]
fn rejected_as(xml: &str, rule: &str, kind: ErrorKind) {
    let e = verify(xml).expect_err(rule);
    assert_eq!((e.rule(), e.kind()), (rule, kind), "{e}");
}

/// The ECDSA signature over `signed_info` with the key of `signer_certificate`: what the
/// caller does with the result.
fn signature_verifies(signed: &SignedTsl) -> bool {
    let certificate = Certificate::from_der(&signed.signer_certificate).unwrap();
    let key = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let key = ecdsa::VerifyingKey::<BrainpoolP256r1>::from_sec1_bytes(key).unwrap();
    let signature = ecdsa::Signature::<BrainpoolP256r1>::from_slice(&signed.signature).unwrap();
    key.verify(&signed.signed_info, &signature).is_ok()
}

#[test]
fn tslsig_010_023_published_tsls_verify() {
    let mut checked = 0;
    for entry in std::fs::read_dir(real()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "xml") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        let signed = verify(&xml).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(signature_verifies(&signed), "{}", path.display());

        let certificate = Certificate::from_der(&signed.signer_certificate).unwrap();
        let serial = certificate.tbs_certificate().serial_number().as_bytes();
        assert_eq!(serial, [signed.signer_serial.parse::<u8>().unwrap()]);
        assert_eq!(
            Base64::encode_string(&Sha256::digest(&signed.signer_certificate)),
            between(&xml, "<xades:CertDigest>", "</xades:CertDigest>")
                .rsplit_once("<ds:DigestValue>")
                .unwrap()
                .1
                .trim_end_matches("</ds:DigestValue>")
        );
        assert!(signed.signing_time.starts_with("2026-"));
        let content = String::from_utf8(signed.content).unwrap();
        assert!(content.starts_with("<TrustServiceStatusList "));
        assert!(!content.contains("SignatureValue"));
        checked += 1;
    }
    assert_eq!(checked, 4);
}

#[test]
fn tslsig_018_signature_is_over_the_canonical_signed_info() {
    let signed = verify(&tsl()).unwrap();
    let mut other = signed.clone();
    other.signed_info.push(b' ');
    assert!(!signature_verifies(&other));
}

#[test]
fn free_in_the_profile() {
    let xml = tsl();
    // Comments are not signed, outside the root or inside the content.
    let (declaration, document) = xml.split_once('\n').unwrap();
    verify(&format!(
        "{declaration}\n<!-- before -->{document}<!-- after -->"
    ))
    .unwrap();
    verify(&edit(
        &xml,
        "<TSLVersionIdentifier>",
        "<!-- c --><TSLVersionIdentifier>",
    ))
    .unwrap();
    // Line breaks and &#xD; inside base64.
    let value = between(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>");
    let wrapped = format!("{}&#xD;\n  {}", &value[..40], &value[40..]);
    verify(&edit(&xml, value, &wrapped)).unwrap();
    // Whitespace between elements of the signature.
    verify(&edit(&xml, "<ds:SignedInfo>", "\n  <ds:SignedInfo>")).unwrap();
    // Unsigned properties are ignored.
    verify(&edit(
        &xml,
        "</xades:SignedProperties>",
        "</xades:SignedProperties><xades:UnsignedProperties><x xmlns=\"urn:x\"/></xades:UnsignedProperties>",
    ))
    .unwrap();
    // Another prefix for the unsigned parts, declared where it is used.
    let key_info = between(&xml, "<ds:KeyInfo>", "</ds:KeyInfo>");
    let renamed = format!(
        "<sig:KeyInfo xmlns:sig=\"http://www.w3.org/2000/09/xmldsig#\">{}</sig:KeyInfo>",
        key_info.replace("ds:", "sig:")
    );
    verify(&edit(
        &xml,
        &format!("<ds:KeyInfo>{key_info}</ds:KeyInfo>"),
        &renamed,
    ))
    .unwrap();
}

#[test]
fn tslsig_010_root_and_the_one_signature() {
    let xml = tsl();
    rejected(
        &edit(
            &xml,
            "xmlns=\"http://uri.etsi.org/02231/v2#\"",
            "xmlns=\"urn:other\"",
        ),
        "TSLSIG-010",
    );
    rejected(
        &edit(
            &xml,
            "</ds:Signature></TrustServiceStatusList>",
            "</ds:Signature><Extra/></TrustServiceStatusList>",
        ),
        "TSLSIG-010",
    );
    let signature = format!(
        "<ds:Signature{}</ds:Signature>",
        between(&xml, "<ds:Signature", "</ds:Signature>")
    );
    rejected(
        &edit(
            &xml,
            "<SchemeInformation>",
            &format!("{signature}<SchemeInformation>"),
        ),
        "TSLSIG-010",
    );
    rejected(&edit(&xml, &signature, ""), "TSLSIG-010");
}

#[test]
fn tslsig_011_canonicalization_method() {
    let xml = tsl();
    let exc = "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">";
    rejected(
        &edit(
            &xml,
            exc,
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">",
        ),
        "TSLSIG-011",
    );
    rejected(
        &edit(
            &xml,
            exc,
            &format!(
                "{exc}<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"ds\"/>"
            ),
        ),
        "TSLSIG-011",
    );
}

#[test]
fn tslsig_012_signature_method() {
    let xml = tsl();
    for other in [
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
    ] {
        rejected(
            &edit(
                &xml,
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                other,
            ),
            "TSLSIG-012",
        );
    }
}

#[test]
fn tslsig_013_references() {
    let xml = tsl();
    let signed_info = between(&xml, "<ds:SignedInfo>", "</ds:SignedInfo>");
    let first = format!(
        "<ds:Reference Id{}</ds:Reference>",
        between(signed_info, "<ds:Reference Id", "</ds:Reference>")
    );
    let second = &signed_info[signed_info.find(&first).unwrap() + first.len()..];

    rejected(
        &edit(
            &xml,
            &format!("{first}{second}"),
            &format!("{second}{first}"),
        ),
        "TSLSIG-013",
    );
    rejected(&edit(&xml, second, ""), "TSLSIG-013");
    rejected(
        &edit(&xml, second, &format!("{second}{second}")),
        "TSLSIG-014",
    );
    rejected(
        &edit(&xml, "URI=\"\"", "URI=\"#ID31033420260927230007Z\""),
        "TSLSIG-013",
    );
    rejected(
        &edit(
            &xml,
            "Type=\"http://uri.etsi.org/01903#SignedProperties\"",
            "",
        ),
        "TSLSIG-013",
    );
    rejected(
        &edit(
            &xml,
            "<ds:Reference Id=\"Reference-TSL",
            "<ds:Reference Foo=\"x\" Id=\"Reference-TSL",
        ),
        "TSLSIG-013",
    );
    rejected(
        &edit(&xml, "URI=\"#SignedProperties", "URI=\"SignedProperties"),
        "TSLSIG-013",
    );
    let c14n_transform = "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms>";
    rejected(
        &edit(
            &xml,
            c14n_transform,
            "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>/</ds:XPath></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms>",
        ),
        "TSLSIG-013",
    );
    rejected(
        &edit(
            &xml,
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>",
            "",
        ),
        "TSLSIG-013",
    );
    rejected(
        &edit(&xml, "<ds:SignedInfo>", "<ds:SignedInfo><!-- c -->"),
        "TSLSIG-013",
    );
    rejected(
        &edit(&xml, "<ds:SignedInfo>", "<ds:SignedInfo Id=\"si\">"),
        "TSLSIG-013",
    );
}

#[test]
fn tslsig_014_ids_and_targets() {
    let xml = tsl();
    let properties_id = between(&xml, "<xades:SignedProperties Id=\"", "\"");
    rejected(
        &edit(
            &xml,
            "<SchemeInformation>",
            &format!("<SchemeInformation Id=\"{properties_id}\">"),
        ),
        "TSLSIG-014",
    );
    // Reference 2 pointing at a signed element outside the XAdES properties.
    rejected(
        &edit(
            &xml,
            &format!("URI=\"#{properties_id}\""),
            "URI=\"#ID31033420260927230007Z\"",
        ),
        "TSLSIG-014",
    );
    rejected(
        &edit(&xml, "Target=\"#Signature", "Target=\"#Other"),
        "TSLSIG-014",
    );
    rejected(
        &edit(&xml, " Id=\"Signature-1790550007771\"", ""),
        "TSLSIG-014",
    );
}

#[test]
fn tslsig_015_digest_methods() {
    let xml = tsl();
    let sha256 = "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\">";
    let sha1 = "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\">";
    for occurrence in 0..3 {
        let at = xml.match_indices(sha256).nth(occurrence).unwrap().0;
        let changed = format!("{}{sha1}{}", &xml[..at], &xml[at + sha256.len()..]);
        rejected(&changed, "TSLSIG-015");
    }
}

#[test]
fn tslsig_017_digests() {
    let xml = tsl();
    rejected(
        &edit(
            &xml,
            "<TSLSequenceNumber>10334<",
            "<TSLSequenceNumber>10335<",
        ),
        "TSLSIG-017",
    );
    rejected(
        &edit(
            &xml,
            "<xades:SigningTime>2026-09-27T23:00:07Z",
            "<xades:SigningTime>2026-09-27T23:00:08Z",
        ),
        "TSLSIG-017",
    );
    let digest = between(&xml, "<ds:DigestValue>", "</ds:DigestValue>");
    rejected(&edit(&xml, digest, &digest[4..]), "TSLSIG-017");
}

#[test]
fn tslsig_018_signature_value() {
    let xml = tsl();
    let value = between(&xml, "<ds:SignatureValue>", "</ds:SignatureValue>");
    let compact: String = value.replace("&#xD;", "").split_whitespace().collect();
    let mut bytes = Base64::decode_vec(&compact).unwrap();
    let with = |bytes: &[u8]| edit(&xml, value, &Base64::encode_string(bytes));

    rejected(&with(&bytes[..63]), "TSLSIG-018");
    rejected(&with(&[bytes.as_slice(), &[0]].concat()), "TSLSIG-018");
    rejected(&edit(&xml, value, "not base64"), "TSLSIG-018");
    rejected(
        &edit(&xml, "<ds:SignatureValue>", "<ds:SignatureValue Id=\"v\">"),
        "TSLSIG-018",
    );

    let order = hex("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7");
    for half in [0..32, 32..64] {
        let original = bytes[half.clone()].to_vec();
        bytes[half.clone()].fill(0);
        rejected(&with(&bytes), "TSLSIG-018");
        bytes[half.clone()].copy_from_slice(&order);
        rejected(&with(&bytes), "TSLSIG-018");
        bytes[half.clone()].fill(0xff);
        rejected(&with(&bytes), "TSLSIG-018");
        bytes[half].copy_from_slice(&original);
    }
    verify(&with(&bytes)).unwrap();
}

#[test]
fn tslsig_019_xades_structure() {
    let xml = tsl();
    let object = format!(
        "<ds:Object>{}</ds:Object>",
        between(&xml, "<ds:Object>", "</ds:Object>")
    );
    rejected(&edit(&xml, &object, ""), "TSLSIG-019");
    rejected(
        &edit(&xml, &object, &format!("{object}<ds:Object/>")),
        "TSLSIG-019",
    );
    rejected(
        &edit(&xml, "<ds:Object>", "<ds:Object Id=\"o\">"),
        "TSLSIG-019",
    );
    rejected(
        &edit(
            &xml,
            "ObjectReference=\"#Reference-TSL",
            "ObjectReference=\"#Other",
        ),
        "TSLSIG-019",
    );
    rejected(&edit(&xml, ">text/xml<", ">application/xml<"), "TSLSIG-019");
    rejected(
        &edit(
            &xml,
            "</xades:QualifyingProperties>",
            "<xades:Other/></xades:QualifyingProperties>",
        ),
        "TSLSIG-019",
    );
    // The data object properties may be absent; then the reference digest changes.
    let data = format!(
        "<xades:SignedDataObjectProperties>{}</xades:SignedDataObjectProperties>",
        between(
            &xml,
            "<xades:SignedDataObjectProperties>",
            "</xades:SignedDataObjectProperties>"
        )
    );
    rejected(&edit(&xml, &data, ""), "TSLSIG-017");
}

#[test]
fn tslsig_020_signing_certificate() {
    let xml = tsl();
    let digest = between(&xml, "<xades:CertDigest>", "</xades:CertDigest>");
    let value = between(digest, "<ds:DigestValue>", "</ds:DigestValue>");
    let other = Base64::encode_string(&Sha256::digest(b"other"));
    rejected(&edit(&xml, value, &other), "TSLSIG-020");
    rejected(
        &edit(&xml, "<ds:X509SerialNumber>6<", "<ds:X509SerialNumber>-6<"),
        "TSLSIG-020",
    );
    rejected(
        &edit(&xml, "<ds:X509SerialNumber>6<", "<ds:X509SerialNumber><"),
        "TSLSIG-020",
    );
    let cert = format!(
        "<xades:Cert>{}</xades:Cert>",
        between(&xml, "<xades:Cert>", "</xades:Cert>")
    );
    rejected(&edit(&xml, &cert, &format!("{cert}{cert}")), "TSLSIG-020");
}

#[test]
fn tslsig_021_signing_time() {
    let xml = tsl();
    rejected(
        &edit(
            &xml,
            "<xades:SigningTime>2026-09-27T23:00:07Z",
            "<xades:SigningTime>27.09.2026 23:00",
        ),
        "TSLSIG-021",
    );
    let time = format!(
        "<xades:SigningTime>{}</xades:SigningTime>",
        between(&xml, "<xades:SigningTime>", "</xades:SigningTime>")
    );
    rejected(&edit(&xml, &time, ""), "TSLSIG-019");
}

#[test]
fn tslsig_022_key_info() {
    let xml = tsl();
    let certificate = format!(
        "<ds:X509Certificate>{}</ds:X509Certificate>",
        between(&xml, "<ds:X509Certificate>", "</ds:X509Certificate>")
    );
    let signer = ErrorKind::SignerCertificate;
    rejected_as(
        &edit(&xml, &certificate, &format!("{certificate}{certificate}")),
        "TSLSIG-022",
        signer,
    );
    rejected_as(&edit(&xml, &certificate, ""), "TSLSIG-022", signer);
    rejected_as(
        &edit(
            &xml,
            &certificate,
            "<ds:X509Certificate>%%</ds:X509Certificate>",
        ),
        "TSLSIG-022",
        signer,
    );
    rejected_as(
        &edit(
            &xml,
            "<ds:X509Data>",
            "<ds:X509Data><ds:X509SubjectName>CN=x</ds:X509SubjectName>",
        ),
        "TSLSIG-022",
        signer,
    );
    rejected_as(
        &edit(
            &xml,
            "<ds:KeyInfo>",
            "<ds:KeyInfo><ds:KeyName>k</ds:KeyName>",
        ),
        "TSLSIG-022",
        signer,
    );
    let key_info = format!(
        "<ds:KeyInfo>{}</ds:KeyInfo>",
        between(&xml, "<ds:KeyInfo>", "</ds:KeyInfo>")
    );
    rejected_as(&edit(&xml, &key_info, ""), "TSLSIG-022", signer);
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
