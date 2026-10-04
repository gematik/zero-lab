//! TSLSIG-010 – 023, the XML side: the enveloped signature of a TSL against the fixed
//! profile, the digests of its two references, and the values the caller verifies with
//! its own algorithms (signature value, signer certificate, serial number).
//!
//! Everything inside `ds:Signature` that the profile does not name is rejected: other
//! elements and attributes, comments, processing instructions and text between elements.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use roxmltree::{Node, NodeType};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::c14n::Subset;
use crate::{Document, Error, ErrorKind};

const TSL: &str = "http://uri.etsi.org/02231/v2#";
const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

/// The order `n` of brainpoolP256r1 (RFC 5639 §3.4, `q`), big-endian.
const BRAINPOOL_P256_ORDER: [u8; 32] = [
    0xa9, 0xfb, 0x57, 0xdb, 0xa1, 0xee, 0xa9, 0xbc, 0x3e, 0x66, 0x0a, 0x90, 0x9d, 0x83, 0x8d, 0x71,
    0x8c, 0x39, 0x7a, 0xa3, 0xb5, 0x61, 0xa6, 0xf7, 0x90, 0x1e, 0x0e, 0x82, 0x97, 0x48, 0x56, 0xa7,
];

/// A TSL whose signature matches the profile and whose reference digests are correct.
///
/// The signature value is not verified and the certificate not parsed: the caller checks
/// [`signature`](Self::signature) over [`signed_info`](Self::signed_info) with the
/// certificate's brainpoolP256r1 key (TSLSIG-012, 018), parses the certificate (TSLSIG-022)
/// and compares its serial number with [`signer_serial`](Self::signer_serial) (TSLSIG-020).
/// Until then nothing here is authentic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignedTsl {
    /// The canonical `SignedInfo` (TSLSIG-016): the message of the ECDSA signature.
    pub signed_info: Vec<u8>,
    /// `SignatureValue` as `r ‖ s`, 32 bytes each, both in `[1, n − 1]` for the order `n`
    /// of brainpoolP256r1 (TSLSIG-018).
    pub signature: [u8; 64],
    /// The DER of the one `KeyInfo` certificate, which `CertDigest` binds (TSLSIG-020,
    /// 022).
    pub signer_certificate: Vec<u8>,
    /// `X509SerialNumber`: the decimal digits as written, surrounding whitespace removed.
    pub signer_serial: String,
    /// `SigningTime`, a lexically valid `xsd:dateTime`; informational (TSLSIG-021).
    pub signing_time: String,
    /// The canonical form of reference 1, the octets that were hashed: the TSL content to
    /// read after the signature is verified (TSLSIG-023).
    pub content: Vec<u8>,
}

impl Document<'_> {
    /// Checks the TSL's enveloped signature against the profile of
    /// `spec/tsl-xmldsig/README.md` and the digests of both references (TSLSIG-010 – 017,
    /// 019 – 023 as far as they concern XML, the encoding of TSLSIG-018).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::SignerCertificate`] if `KeyInfo` does not hold exactly one
    /// certificate; [`ErrorKind::Signature`] for every other deviation from the profile and
    /// for a digest that does not match. [`Error::rule`] names the rule.
    pub fn verify_tsl_signature(&self) -> Result<SignedTsl, Error> {
        let root = self.tree.root_element();
        if !is(root, TSL, "TrustServiceStatusList") {
            return Err(invalid(
                "TSLSIG-010",
                format!("root element {:?} is not a TSL", root.tag_name().name()),
            ));
        }
        let signature_element = the_signature(self, root)?;
        check_unique_ids(self)?;
        attributes(signature_element, &["Id"], "TSLSIG-014")?;
        let signature_id = required(signature_element, "Id", "TSLSIG-014")?;

        let [signed_info, signature_value, key_info, object] =
            signature_children(signature_element)?;
        let [reference_1, reference_2] = check_signed_info(signed_info)?;
        let signed_properties = check_object(object, signature_id, reference_1.id)?;

        let target = reference_2
            .uri
            .strip_prefix('#')
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                invalid(
                    "TSLSIG-013",
                    format!("reference 2 URI {:?} is not #id", reference_2.uri),
                )
            })?;
        if self.element_by_id(target)?.id() != signed_properties.node.id() {
            return Err(invalid(
                "TSLSIG-014",
                "reference 2 does not resolve to this signature's SignedProperties",
            ));
        }

        let signer_certificate = check_key_info(key_info)?;
        if !digest_matches(&signer_certificate, &signed_properties.cert_digest) {
            return Err(invalid(
                "TSLSIG-020",
                "CertDigest is not the SHA-256 of the KeyInfo certificate",
            ));
        }
        let signature = check_signature_value(signature_value)?;

        let content = self.canonicalize(Subset::Document {
            omit: Some(signature_element.id()),
        })?;
        if !digest_matches(&content, &reference_1.digest) {
            return Err(invalid("TSLSIG-017", "reference 1: digest mismatch"));
        }
        let properties = self.canonicalize(Subset::Element(signed_properties.node.id()))?;
        if !digest_matches(&properties, &reference_2.digest) {
            return Err(invalid("TSLSIG-017", "reference 2: digest mismatch"));
        }

        Ok(SignedTsl {
            signed_info: self.canonicalize(Subset::Element(signed_info.id()))?,
            signature,
            signer_certificate,
            signer_serial: signed_properties.serial,
            signing_time: signed_properties.signing_time,
            content,
        })
    }
}

/// TSLSIG-010: the one `ds:Signature` of the document, the root's last element child.
fn the_signature<'d, 'a>(
    document: &'d Document<'a>,
    root: Node<'d, 'a>,
) -> Result<Node<'d, 'a>, Error> {
    let mut signatures = document
        .tree
        .descendants()
        .filter(|n| is(*n, DS, "Signature"));
    let signature = match (signatures.next(), signatures.next()) {
        (Some(s), None) => s,
        (None, _) => return Err(invalid("TSLSIG-010", "no ds:Signature")),
        (Some(_), Some(_)) => return Err(invalid("TSLSIG-010", "more than one ds:Signature")),
    };
    let last = root.children().rfind(Node::is_element);
    if last.map(|n| n.id()) != Some(signature.id()) {
        return Err(invalid(
            "TSLSIG-010",
            "ds:Signature is not the last element child of the root",
        ));
    }
    Ok(signature)
}

/// TSLSIG-014: no two elements share a value of the attribute `Id`.
fn check_unique_ids(document: &Document<'_>) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for id in document
        .tree
        .descendants()
        .filter_map(|n| n.attribute("Id"))
    {
        if !seen.insert(id) {
            return Err(invalid(
                "TSLSIG-014",
                format!("several elements have Id {id:?}"),
            ));
        }
    }
    Ok(())
}

/// `SignedInfo`, `SignatureValue`, `KeyInfo`, `Object`, in that order and nothing else.
fn signature_children<'d, 'a>(signature: Node<'d, 'a>) -> Result<[Node<'d, 'a>; 4], Error> {
    let children = element_children(signature, "TSLSIG-013")?;
    let count = |local| children.iter().filter(|n| is(**n, DS, local)).count();
    if count("KeyInfo") != 1 {
        return Err(Error::new(
            ErrorKind::SignerCertificate,
            "TSLSIG-022",
            "ds:Signature does not have exactly one KeyInfo",
        ));
    }
    if count("Object") != 1 {
        return Err(invalid(
            "TSLSIG-019",
            "ds:Signature does not have exactly one ds:Object",
        ));
    }
    let names = ["SignedInfo", "SignatureValue", "KeyInfo", "Object"];
    match <[Node<'d, 'a>; 4]>::try_from(children) {
        Ok(nodes) if nodes.iter().zip(names).all(|(n, local)| is(*n, DS, local)) => Ok(nodes),
        _ => Err(invalid(
            "TSLSIG-013",
            "ds:Signature is not SignedInfo, SignatureValue, KeyInfo, Object",
        )),
    }
}

/// A reference of `SignedInfo` that matches the profile.
struct Reference<'a> {
    id: Option<&'a str>,
    uri: &'a str,
    digest: Vec<u8>,
}

/// TSLSIG-011 – 013, 015: the two algorithms and the two references, nothing else.
fn check_signed_info<'d>(signed_info: Node<'d, '_>) -> Result<[Reference<'d>; 2], Error> {
    attributes(signed_info, &[], "TSLSIG-013")?;
    let [c14n, method, first, second] = sequence(
        signed_info,
        "TSLSIG-013",
        [
            (DS, "CanonicalizationMethod"),
            (DS, "SignatureMethod"),
            (DS, "Reference"),
            (DS, "Reference"),
        ],
    )?;
    algorithm(c14n, EXC_C14N, "TSLSIG-011")?;
    algorithm(method, ECDSA_SHA256, "TSLSIG-012")?;

    attributes(first, &["Id", "URI"], "TSLSIG-013")?;
    let reference_1 = reference(first, &[ENVELOPED, EXC_C14N])?;
    if !reference_1.uri.is_empty() {
        return Err(invalid(
            "TSLSIG-013",
            format!("reference 1 URI {:?} is not \"\"", reference_1.uri),
        ));
    }

    attributes(second, &["Id", "Type", "URI"], "TSLSIG-013")?;
    if second.attribute("Type") != Some(SIGNED_PROPERTIES) {
        return Err(invalid(
            "TSLSIG-013",
            "reference 2 does not have Type SignedProperties",
        ));
    }
    let reference_2 = reference(second, &[EXC_C14N])?;
    Ok([reference_1, reference_2])
}

/// `Transforms` with exactly `transforms`, `DigestMethod` SHA-256, a 32-byte
/// `DigestValue`.
fn reference<'d>(node: Node<'d, '_>, transforms: &[&str]) -> Result<Reference<'d>, Error> {
    let uri = required(node, "URI", "TSLSIG-013")?;
    let [list, method, value] = sequence(
        node,
        "TSLSIG-013",
        [
            (DS, "Transforms"),
            (DS, "DigestMethod"),
            (DS, "DigestValue"),
        ],
    )?;
    attributes(list, &[], "TSLSIG-013")?;
    let written = element_children(list, "TSLSIG-013")?;
    if written.len() != transforms.len() {
        return Err(invalid(
            "TSLSIG-013",
            format!("a reference has {} transforms", written.len()),
        ));
    }
    for (transform, expected) in written.into_iter().zip(transforms) {
        if !is(transform, DS, "Transform") {
            return Err(invalid("TSLSIG-013", "Transforms has another element"));
        }
        algorithm(transform, expected, "TSLSIG-013")?;
    }
    algorithm(method, SHA256, "TSLSIG-015")?;
    Ok(Reference {
        id: node.attribute("Id"),
        uri,
        digest: digest_value(value)?,
    })
}

/// The checked content of `xades:SignedProperties`.
struct SignedProperties<'d, 'a> {
    node: Node<'d, 'a>,
    cert_digest: Vec<u8>,
    serial: String,
    signing_time: String,
}

/// TSLSIG-019 – 021: one `ds:Object` with one `QualifyingProperties` targeting this
/// signature, its `SignedProperties` and, ignored, its `UnsignedProperties`.
fn check_object<'d, 'a>(
    object: Node<'d, 'a>,
    signature_id: &str,
    reference_1_id: Option<&str>,
) -> Result<SignedProperties<'d, 'a>, Error> {
    attributes(object, &[], "TSLSIG-019")?;
    let [qualifying] = sequence(object, "TSLSIG-019", [(XADES, "QualifyingProperties")])?;
    attributes(qualifying, &["Target"], "TSLSIG-014")?;
    let target = required(qualifying, "Target", "TSLSIG-014")?;
    if target.strip_prefix('#') != Some(signature_id) {
        return Err(invalid(
            "TSLSIG-014",
            format!("QualifyingProperties Target {target:?} is not #{signature_id}"),
        ));
    }
    let properties = match element_children(qualifying, "TSLSIG-019")?.as_slice() {
        [signed] if is(*signed, XADES, "SignedProperties") => *signed,
        [signed, unsigned]
            if is(*signed, XADES, "SignedProperties")
                && is(*unsigned, XADES, "UnsignedProperties") =>
        {
            *signed
        }
        _ => {
            return Err(invalid(
                "TSLSIG-019",
                "QualifyingProperties is not SignedProperties and optional UnsignedProperties",
            ));
        }
    };
    attributes(properties, &["Id"], "TSLSIG-014")?;
    required(properties, "Id", "TSLSIG-014")?;

    let signature_properties = match element_children(properties, "TSLSIG-019")?.as_slice() {
        [signature] if is(*signature, XADES, "SignedSignatureProperties") => *signature,
        [signature, data]
            if is(*signature, XADES, "SignedSignatureProperties")
                && is(*data, XADES, "SignedDataObjectProperties") =>
        {
            check_data_object_properties(*data, reference_1_id)?;
            *signature
        }
        _ => {
            return Err(invalid(
                "TSLSIG-019",
                "SignedProperties is not SignedSignatureProperties and optional \
                 SignedDataObjectProperties",
            ));
        }
    };
    attributes(signature_properties, &[], "TSLSIG-019")?;
    let [time, certificate] = sequence(
        signature_properties,
        "TSLSIG-019",
        [(XADES, "SigningTime"), (XADES, "SigningCertificate")],
    )?;

    attributes(time, &[], "TSLSIG-021")?;
    let signing_time = String::from(trim(&text(time, "TSLSIG-021")?));
    if !is_date_time(&signing_time) {
        return Err(invalid(
            "TSLSIG-021",
            format!("SigningTime {signing_time:?} is not an xsd:dateTime"),
        ));
    }

    let (cert_digest, serial) = check_signing_certificate(certificate)?;
    Ok(SignedProperties {
        node: properties,
        cert_digest,
        serial,
        signing_time,
    })
}

/// TSLSIG-019: one `DataObjectFormat`, for reference 1, of MIME type `text/xml`.
fn check_data_object_properties(
    data: Node<'_, '_>,
    reference_1_id: Option<&str>,
) -> Result<(), Error> {
    attributes(data, &[], "TSLSIG-019")?;
    let [format] = sequence(data, "TSLSIG-019", [(XADES, "DataObjectFormat")])?;
    attributes(format, &["ObjectReference"], "TSLSIG-019")?;
    let points_to = required(format, "ObjectReference", "TSLSIG-019")?.strip_prefix('#');
    if reference_1_id.is_none() || points_to != reference_1_id {
        return Err(invalid(
            "TSLSIG-019",
            "DataObjectFormat does not point to reference 1",
        ));
    }
    let [mime_type] = sequence(format, "TSLSIG-019", [(XADES, "MimeType")])?;
    attributes(mime_type, &[], "TSLSIG-019")?;
    if trim(&text(mime_type, "TSLSIG-019")?) != "text/xml" {
        return Err(invalid(
            "TSLSIG-019",
            "DataObjectFormat MimeType is not text/xml",
        ));
    }
    Ok(())
}

/// TSLSIG-015, 020: one `Cert` with a SHA-256 `CertDigest` and an `IssuerSerial`.
/// Returns the digest and the serial number.
fn check_signing_certificate(certificate: Node<'_, '_>) -> Result<(Vec<u8>, String), Error> {
    attributes(certificate, &[], "TSLSIG-020")?;
    let [cert] = sequence(certificate, "TSLSIG-020", [(XADES, "Cert")])?;
    attributes(cert, &[], "TSLSIG-020")?;
    let [digest, issuer_serial] = sequence(
        cert,
        "TSLSIG-020",
        [(XADES, "CertDigest"), (XADES, "IssuerSerial")],
    )?;
    attributes(digest, &[], "TSLSIG-020")?;
    let [method, value] = sequence(
        digest,
        "TSLSIG-020",
        [(DS, "DigestMethod"), (DS, "DigestValue")],
    )?;
    algorithm(method, SHA256, "TSLSIG-015")?;
    let cert_digest = digest_value(value)?;

    attributes(issuer_serial, &[], "TSLSIG-020")?;
    let [issuer, serial] = sequence(
        issuer_serial,
        "TSLSIG-020",
        [(DS, "X509IssuerName"), (DS, "X509SerialNumber")],
    )?;
    attributes(issuer, &[], "TSLSIG-020")?;
    text(issuer, "TSLSIG-020")?;
    attributes(serial, &[], "TSLSIG-020")?;
    let serial = String::from(trim(&text(serial, "TSLSIG-020")?));
    if serial.is_empty() || !serial.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "TSLSIG-020",
            format!("X509SerialNumber {serial:?} is not a non-negative integer"),
        ));
    }
    Ok((cert_digest, serial))
}

/// TSLSIG-022: `KeyInfo` holds one `X509Data` with one `X509Certificate`; its DER.
fn check_key_info(key_info: Node<'_, '_>) -> Result<Vec<u8>, Error> {
    let fail =
        |detail: &'static str| Error::new(ErrorKind::SignerCertificate, "TSLSIG-022", detail);
    let only_child = |node: Node<'_, '_>, local: &str| -> Result<(), Error> {
        let children = element_children(node, "TSLSIG-022")
            .map_err(|_| fail("KeyInfo holds more than X509Data/X509Certificate"))?;
        match children.as_slice() {
            [child] if is(*child, DS, local) && child.attributes().len() == 0 => Ok(()),
            _ => Err(fail(
                "KeyInfo is not exactly one X509Data with one X509Certificate",
            )),
        }
    };
    if key_info.attributes().len() != 0 {
        return Err(fail("KeyInfo has attributes"));
    }
    only_child(key_info, "X509Data")?;
    let data = key_info
        .first_element_child()
        .ok_or_else(|| fail("KeyInfo without X509Data"))?;
    only_child(data, "X509Certificate")?;
    let certificate = data
        .first_element_child()
        .ok_or_else(|| fail("X509Data without X509Certificate"))?;
    let base64 = text(certificate, "TSLSIG-022")
        .map_err(|_| fail("X509Certificate holds more than base64"))?;
    match decode_base64(&base64) {
        Some(der) if !der.is_empty() => Ok(der),
        _ => Err(fail("X509Certificate is not base64")),
    }
}

/// TSLSIG-018: base64 of exactly 64 bytes, `r ‖ s`, both in `[1, n − 1]`.
fn check_signature_value(node: Node<'_, '_>) -> Result<[u8; 64], Error> {
    attributes(node, &[], "TSLSIG-018")?;
    let decoded = decode_base64(&text(node, "TSLSIG-018")?)
        .ok_or_else(|| invalid("TSLSIG-018", "SignatureValue is not base64"))?;
    let signature = <[u8; 64]>::try_from(decoded).map_err(|d| {
        invalid(
            "TSLSIG-018",
            format!("SignatureValue has {} bytes, not 64", d.len()),
        )
    })?;
    let in_range = |half: Option<&[u8; 32]>| {
        half.is_some_and(|x| x.iter().any(|b| *b != 0) && *x < BRAINPOOL_P256_ORDER)
    };
    if !in_range(signature.first_chunk()) || !in_range(signature.last_chunk()) {
        return Err(invalid(
            "TSLSIG-018",
            "r or s is not in [1, n − 1] for brainpoolP256r1",
        ));
    }
    Ok(signature)
}

/// A `DigestValue`: no attributes, base64 of exactly 32 bytes.
fn digest_value(node: Node<'_, '_>) -> Result<Vec<u8>, Error> {
    attributes(node, &[], "TSLSIG-017")?;
    match decode_base64(&text(node, "TSLSIG-017")?) {
        Some(digest) if digest.len() == 32 => Ok(digest),
        _ => Err(invalid(
            "TSLSIG-017",
            "DigestValue is not base64 of 32 bytes",
        )),
    }
}

/// TSLSIG-017: SHA-256 of `data` equals `expected`, compared in constant time.
fn digest_matches(data: &[u8], expected: &[u8]) -> bool {
    Sha256::digest(data).as_slice().ct_eq(expected).into()
}

/// An element with only the attribute `Algorithm`, equal to `uri`, and no content.
fn algorithm(node: Node<'_, '_>, uri: &str, rule: &'static str) -> Result<(), Error> {
    attributes(node, &["Algorithm"], rule)?;
    let written = required(node, "Algorithm", rule)?;
    if written != uri {
        return Err(invalid(
            rule,
            format!(
                "{} Algorithm {written:?} is not {uri}",
                node.tag_name().name()
            ),
        ));
    }
    if !element_children(node, rule)?.is_empty() {
        return Err(invalid(
            rule,
            format!("{} has child elements", node.tag_name().name()),
        ));
    }
    Ok(())
}

/// The element children of `node`, exactly as many as `expected`, with those names.
fn sequence<'d, 'a, const N: usize>(
    node: Node<'d, 'a>,
    rule: &'static str,
    expected: [(&str, &str); N],
) -> Result<[Node<'d, 'a>; N], Error> {
    let fail = || {
        let names: Vec<&str> = expected.iter().map(|(_, local)| *local).collect();
        invalid(
            rule,
            format!(
                "{} does not contain exactly {}",
                node.tag_name().name(),
                names.join(", ")
            ),
        )
    };
    let children =
        <[Node<'d, 'a>; N]>::try_from(element_children(node, rule)?).map_err(|_| fail())?;
    if children
        .iter()
        .zip(expected)
        .all(|(n, (namespace, local))| is(*n, namespace, local))
    {
        Ok(children)
    } else {
        Err(fail())
    }
}

/// The element children of `node`; between them only whitespace.
fn element_children<'d, 'a>(
    node: Node<'d, 'a>,
    rule: &'static str,
) -> Result<Vec<Node<'d, 'a>>, Error> {
    let mut elements = Vec::new();
    for child in node.children() {
        match child.node_type() {
            NodeType::Element => elements.push(child),
            NodeType::Text if trim(child.text().unwrap_or_default()).is_empty() => {}
            _ => {
                return Err(invalid(
                    rule,
                    format!(
                        "{} contains text, a comment or a processing instruction",
                        node.tag_name().name()
                    ),
                ));
            }
        }
    }
    Ok(elements)
}

/// The character data of an element that holds nothing else.
fn text(node: Node<'_, '_>, rule: &'static str) -> Result<String, Error> {
    let mut text = String::new();
    for child in node.children() {
        match child.text() {
            Some(t) if child.is_text() => text.push_str(t),
            _ => {
                return Err(invalid(
                    rule,
                    format!("{} holds more than text", node.tag_name().name()),
                ));
            }
        }
    }
    Ok(text)
}

/// No attributes besides `allowed`, which are unqualified; namespace declarations are
/// not attributes here.
fn attributes(node: Node<'_, '_>, allowed: &[&str], rule: &'static str) -> Result<(), Error> {
    match node
        .attributes()
        .find(|a| a.namespace().is_some() || !allowed.contains(&a.name()))
    {
        None => Ok(()),
        Some(a) => Err(invalid(
            rule,
            format!(
                "{} has the attribute {:?}",
                node.tag_name().name(),
                a.name()
            ),
        )),
    }
}

fn required<'d>(node: Node<'d, '_>, name: &str, rule: &'static str) -> Result<&'d str, Error> {
    node.attribute(name)
        .ok_or_else(|| invalid(rule, format!("{} without {name}", node.tag_name().name())))
}

fn is(node: Node<'_, '_>, namespace: &str, local: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == local
        && node.tag_name().namespace() == Some(namespace)
}

fn invalid(rule: &'static str, detail: impl Into<alloc::borrow::Cow<'static, str>>) -> Error {
    Error::new(ErrorKind::Signature, rule, detail)
}

fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn trim(text: &str) -> &str {
    text.trim_matches(is_xml_space)
}

/// Base64 with XML whitespace anywhere ignored (`&#xD;` arrives here as a carriage
/// return); padding and unused bits as RFC 4648 requires.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !is_xml_space(*c)).collect();
    Base64::decode_vec(&compact).ok()
}

/// Whether `value` is the lexical form of an `xsd:dateTime` (XML Schema 1.1 Part 2
/// §3.3.7): `-?YYYY-MM-DDThh:mm:ss(.s+)?` with an optional zone `Z` or `±hh:mm`.
fn is_date_time(value: &str) -> bool {
    let Some((date, time)) = value.split_once('T') else {
        return false;
    };
    let date = date.strip_prefix('-').unwrap_or(date);
    let mut fields = date.splitn(3, '-');
    let (Some(year), Some(month), Some(day)) = (fields.next(), fields.next(), fields.next()) else {
        return false;
    };
    let year_ok = year.len() >= 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !(year.len() > 4 && year.starts_with('0'));
    let (Some(month), Some(day)) = (two_digits(month), two_digits(day)) else {
        return false;
    };
    let leap = year_leap(year);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if !year_ok || day == 0 || day > days {
        return false;
    }

    let (clock, zone) = match time.strip_suffix('Z') {
        Some(clock) => (clock, None),
        None => match time.rfind(['+', '-']) {
            Some(at) => (
                time.get(..at).unwrap_or_default(),
                time.get(at.saturating_add(1)..),
            ),
            None => (time, None),
        },
    };
    if let Some(zone) = zone {
        let Some((h, m)) = zone.split_once(':') else {
            return false;
        };
        match (two_digits(h), two_digits(m)) {
            (Some(h), Some(m)) if h < 14 && m < 60 => {}
            (Some(14), Some(0)) => {}
            _ => return false,
        }
    }
    let mut fields = clock.splitn(3, ':');
    let (Some(h), Some(m), Some(s)) = (fields.next(), fields.next(), fields.next()) else {
        return false;
    };
    let (whole, fraction) = match s.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (s, None),
    };
    if fraction.is_some_and(|f| f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    match (two_digits(h), two_digits(m), two_digits(whole)) {
        (Some(h), Some(m), Some(s)) if h < 24 && m < 60 && s < 60 => true,
        // 24:00:00 is the end of the day.
        (Some(24), Some(0), Some(0)) => fraction.is_none_or(|f| f.bytes().all(|b| b == b'0')),
        _ => false,
    }
}

fn two_digits(field: &str) -> Option<u8> {
    match field.as_bytes() {
        [a, b] if a.is_ascii_digit() && b.is_ascii_digit() => Some(
            a.wrapping_sub(b'0')
                .wrapping_mul(10)
                .wrapping_add(b.wrapping_sub(b'0')),
        ),
        _ => None,
    }
}

/// Gregorian leap year, for a year of any number of decimal digits.
fn year_leap(year: &str) -> bool {
    let rest = year.bytes().fold(0u32, |r, d| {
        r.wrapping_mul(10)
            .wrapping_add(u32::from(d.wrapping_sub(b'0')))
            % 400
    });
    rest % 4 == 0 && (rest % 100 != 0 || rest == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tslsig_018_order_is_brainpool_p256r1() {
        use bp256::elliptic_curve::PrimeField;
        let n = BRAINPOOL_P256_ORDER;
        assert!(bool::from(bp256::r1::Scalar::from_repr(n.into()).is_none()));
        let mut below = n;
        if let Some(last) = below.last_mut() {
            *last -= 1;
        }
        assert!(bool::from(
            bp256::r1::Scalar::from_repr(below.into()).is_some()
        ));
    }

    #[test]
    fn tslsig_021_date_times() {
        for ok in [
            "2026-09-27T23:00:07Z",
            "2026-04-09T08:19:03.300+02:00",
            "2024-02-29T00:00:00",
            "2000-02-29T24:00:00Z",
            "-0044-03-15T12:00:00-14:00",
            "12026-01-01T00:00:00.5+14:00",
        ] {
            assert!(is_date_time(ok), "{ok}");
        }
        for bad in [
            "",
            "2026-09-27",
            "2026-09-27 23:00:07Z",
            "26-09-27T23:00:07Z",
            "02026-09-27T23:00:07Z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-09-27T24:00:01Z",
            "2026-09-27T23:60:00Z",
            "2026-09-27T23:00:60Z",
            "2026-09-27T23:00:07.Z",
            "2026-09-27T23:00:07+14:30",
            "2026-09-27T23:00:07+0200",
            "2026-09-27T23:00:07z",
        ] {
            assert!(!is_date_time(bad), "{bad}");
        }
    }

    #[test]
    fn base64_ignores_xml_whitespace_only() {
        assert_eq!(decode_base64(" YW\r\nJj\t").unwrap(), b"abc");
        assert!(decode_base64("YWJj\u{a0}").is_none());
        assert!(decode_base64("YWI").is_none());
        assert!(decode_base64("YWJ=").is_none());
    }
}
