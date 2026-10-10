//! The SMC-B authentication identity (AUT): a certificate with digitalSignature and
//! without contentCommitment, and the key that signs for it. From a PKCS#12 file, a PEM
//! certificate and key, or a card at the Konnektor; the commands see one [`Identity`]
//! whichever it was.

use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use der::Decode as _;
use der::asn1::ObjectIdentifier;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::SignatureAlgorithm;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::keys::{JwsKey, Signature, Signer, SoftwareKey};
use jwz_brainpool::BrainpoolEs256Key;
use sha2::{Digest, Sha256};
use ti_connector_client::SignatureType;
use ti_connector_client::types::{CertRef, Crypt};
use ti_pki::Certificate;
use x509_cert::ext::pkix::KeyUsages;
use zeroize::Zeroizing;

use crate::block::block_on;
use crate::cli::{ConnectorArgs, GlobalArgs, IdentityArgs};
use crate::connector::{self, Session};
use crate::error::CliError;
use crate::input;
use crate::output::Output;

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const BRAINPOOL_P256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The curves an SMC-B authentication key is on (gemSpec_Krypt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    /// brainpoolP256r1, the cards in the field.
    Brainpool,
    /// P-256, the migration target.
    P256,
}

impl Curve {
    /// The name `pki inspect` uses.
    pub const fn name(self) -> &'static str {
        match self {
            Curve::Brainpool => "brainpoolP256r1",
            Curve::P256 => "P-256",
        }
    }

    /// The JWK `crv`.
    const fn crv(self) -> &'static str {
        match self {
            Curve::Brainpool => "BP-256",
            Curve::P256 => "P-256",
        }
    }

    fn from_oid(oid: &ObjectIdentifier) -> Option<Curve> {
        match *oid {
            BRAINPOOL_P256R1 => Some(Curve::Brainpool),
            SECP256R1 => Some(Curve::P256),
            _ => None,
        }
    }

    /// The curve of the certificate's key, if it is one an identity signs with.
    fn of_certificate(cert: &Certificate) -> Option<Curve> {
        let info = cert.public_key_info();
        if info.algorithm.oid != ID_EC_PUBLIC_KEY {
            return None;
        }
        let oid = info
            .algorithm
            .parameters
            .as_ref()?
            .decode_as::<ObjectIdentifier>()
            .ok()?;
        Curve::from_oid(&oid)
    }
}

/// Where an identity came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A PKCS#12 file.
    P12,
    /// A PEM certificate and a PEM key.
    Pem,
    /// A card at the Konnektor.
    Connector,
}

/// The identity: its certificate, the certificates found with it, and its signer.
pub struct Identity {
    /// Where it came from.
    pub kind: SourceKind,
    /// The file, or `NAME card CARD` for a Konnektor (NAME its configuration).
    pub name: String,
    /// The AUT certificate.
    pub certificate: Certificate,
    /// The other certificates of the source (CAs), chain candidates.
    pub chain: Vec<Certificate>,
    /// The key's curve.
    pub curve: Curve,
    signer: Box<dyn Signer>,
    connector: Option<Rc<ConnectorKey>>,
}

impl Identity {
    /// The identity `args` name, loaded and ready to sign.
    ///
    /// # Errors
    ///
    /// Reading and decoding errors of the source; [`CliError::IdentityNotFound`] when no
    /// AUT certificate with its key is there; [`CliError::KeyUnsupported`] for a key
    /// that is not ECDSA on brainpoolP256r1 or P-256.
    pub fn load(
        args: &IdentityArgs,
        global: &GlobalArgs,
        out: &Output,
    ) -> Result<Identity, CliError> {
        if let Some(path) = &args.p12 {
            let password = input::p12_password(&args.password)?;
            return from_p12(path, &password);
        }
        if let (Some(cert), Some(key)) = (&args.cert, &args.key) {
            return from_pem(cert, key);
        }
        if let Some(card) = &args.card {
            return from_connector(args.connector.as_deref(), card, global, out);
        }
        // clap requires one of the three.
        Err(CliError::IdentityNotFound("no identity given".into()))
    }

    /// The Telematik-ID: the admission statement's registration number.
    pub fn telematik_id(&self) -> Option<String> {
        self.certificate
            .admission()
            .ok()
            .flatten()
            .and_then(|a| a.registration_number)
    }

    /// `payload` as a compact JWS signed by this identity: `alg` from the key, `x5c`
    /// the certificate, the rest from `params`.
    ///
    /// # Errors
    ///
    /// [`CliError::Connector`] when the Konnektor refused to sign;
    /// [`CliError::Signing`] otherwise.
    pub fn sign(&self, payload: &[u8], params: HeaderParams) -> Result<String, CliError> {
        let params = params.x5c(&[self.certificate.der()]);
        jwz::jws::sign(payload, params, &*self.signer).map_err(|error| {
            match self.connector.as_ref().and_then(|key| key.take_error()) {
                Some(connector) => CliError::Connector(connector),
                None => CliError::Signing(error.to_string()),
            }
        })
    }
}

/// A private key with its curve, as PKCS#8 or SEC1 encode it.
struct PrivateKey {
    curve: Curve,
    scalar: Zeroizing<Vec<u8>>,
}

impl PrivateKey {
    /// From PKCS#8 `PrivateKeyInfo` DER.
    fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, CliError> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(der)
            .map_err(|e| CliError::KeyUnsupported(format!("not a PKCS#8 key: {e}")))?;
        if info.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(CliError::KeyUnsupported(format!(
                "key algorithm {} is not id-ecPublicKey",
                info.algorithm.oid
            )));
        }
        let curve = info
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        Self::from_sec1(info.private_key.as_bytes(), curve.as_ref())
    }

    /// From SEC1 `ECPrivateKey` DER; `curve` from the PKCS#8 header when the key does
    /// not name its own.
    fn from_sec1(der: &[u8], curve: Option<&ObjectIdentifier>) -> Result<PrivateKey, CliError> {
        let key = sec1::EcPrivateKey::from_der(der)
            .map_err(|e| CliError::KeyUnsupported(format!("not an EC private key: {e}")))?;
        let named = match key.parameters {
            Some(sec1::EcParameters::NamedCurve(oid)) => Some(oid),
            None => curve.copied(),
        };
        let oid =
            named.ok_or_else(|| CliError::KeyUnsupported("EC key without a named curve".into()))?;
        let curve = Curve::from_oid(&oid).ok_or_else(|| {
            CliError::KeyUnsupported(format!("curve {oid} is not brainpoolP256r1 or P-256"))
        })?;
        if key.private_key.len() != 32 {
            return Err(CliError::KeyUnsupported(format!(
                "private scalar of {} bytes, expected 32",
                key.private_key.len()
            )));
        }
        Ok(PrivateKey {
            curve,
            scalar: Zeroizing::new(key.private_key.to_vec()),
        })
    }

    /// From a PEM file: `PRIVATE KEY` (PKCS#8) or `EC PRIVATE KEY` (SEC1).
    fn from_pem(pem: &[u8], name: &str) -> Result<PrivateKey, CliError> {
        let (label, der) = pem_rfc7468::decode_vec(pem)
            .map_err(|e| CliError::KeyUnsupported(format!("{name}: {e}")))?;
        match label {
            "PRIVATE KEY" => Self::from_pkcs8(&der),
            "EC PRIVATE KEY" => Self::from_sec1(&der, None),
            "ENCRYPTED PRIVATE KEY" => Err(CliError::KeyUnsupported(format!(
                "{name}: encrypted PKCS#8 keys are not supported; use a PKCS#12 file"
            ))),
            other => Err(CliError::KeyUnsupported(format!(
                "{name}: a {other} block is not a private key"
            ))),
        }
    }

    /// A signer for `cert`, if this is its key: the public point is the certificate's.
    fn signer_for(&self, cert: &Certificate) -> Option<Box<dyn Signer>> {
        if Curve::of_certificate(cert) != Some(self.curve) {
            return None;
        }
        let mut material = EcKey::from_point(self.curve.crv(), cert.public_key());
        material.d = Some(Secret::new(self.scalar.to_vec()));
        let jwk = Jwk::new(KeyMaterial::Ec(material));
        // Both constructors refuse a private scalar that does not belong to the point.
        match self.curve {
            Curve::Brainpool => BrainpoolEs256Key::from_jwk(&jwk)
                .ok()
                .map(|key| Box::new(key) as Box<dyn Signer>),
            Curve::P256 => SoftwareKey::from_jwk(
                &jwk,
                SignatureAlgorithm::ES256,
                &jwz_brainpool::registry(),
                Arc::new(RustCrypto::new()),
            )
            .ok()
            .map(|key| Box::new(key) as Box<dyn Signer>),
        }
    }
}

/// Whether `cert` is an authentication certificate: digitalSignature set,
/// contentCommitment (nonRepudiation, the OSIG certificate's mark) not set.
fn is_aut(cert: &Certificate) -> bool {
    cert.key_usage().is_some_and(|ku| {
        let usages = ku.0;
        usages.contains(KeyUsages::DigitalSignature) && !usages.contains(KeyUsages::NonRepudiation)
    })
}

/// The AUT pair among `candidates` (certificates with a key each), the rest as the chain
/// together with `others`.
fn select(
    kind: SourceKind,
    name: &str,
    candidates: Vec<(Certificate, PrivateKey)>,
    others: Vec<Certificate>,
) -> Result<Identity, CliError> {
    let mut seen = Vec::new();
    // A sibling identity (OSIG, ENC) is not a chain candidate; only the CAs are.
    let chain = others;
    let mut found: Option<(Certificate, Box<dyn Signer>, Curve)> = None;
    for (cert, key) in candidates {
        if found.is_none() && is_aut(&cert) {
            match key.signer_for(&cert) {
                Some(signer) => found = Some((cert, signer, key.curve)),
                None => seen.push(format!("{} (key does not match)", cert.subject_cn())),
            }
        } else {
            seen.push(format!(
                "{} ({})",
                cert.subject_cn(),
                if is_aut(&cert) {
                    "another AUT"
                } else {
                    "not an AUT key usage"
                }
            ));
        }
    }
    let Some((certificate, signer, curve)) = found else {
        let what = if seen.is_empty() {
            "no certificate with its key".to_owned()
        } else {
            format!("with their keys: {}", seen.join(", "))
        };
        return Err(CliError::IdentityNotFound(format!("{name}: {what}")));
    };
    Ok(Identity {
        kind,
        name: name.to_owned(),
        certificate,
        chain,
        curve,
        signer,
        connector: None,
    })
}

fn from_p12(path: &Path, password: &str) -> Result<Identity, CliError> {
    let source = input::read(path)?;
    let p12 = ti_pkcs12::decode(&source.bytes, password).map_err(|error| CliError::Pkcs12 {
        source_name: source.name.clone(),
        source: error,
    })?;
    let certificate_error = |error| CliError::Certificate {
        source_name: source.name.clone(),
        source: error,
    };
    let pairs = p12.pairs();
    let mut candidates = Vec::new();
    let mut others = Vec::new();
    for (i, bag) in p12.certificates.iter().enumerate() {
        let cert = Certificate::from_der(&bag.der).map_err(certificate_error)?;
        match pairs.iter().find(|pair| pair.certificate == i) {
            Some(pair) => {
                let key = PrivateKey::from_pkcs8(&p12.keys[pair.key].pkcs8)?;
                candidates.push((cert, key));
            }
            None => others.push(cert),
        }
    }
    select(SourceKind::P12, &source.name, candidates, others)
}

fn from_pem(cert_path: &Path, key_path: &Path) -> Result<Identity, CliError> {
    let certs = input::read(cert_path)?;
    let mut certificates = input::certificates(&certs, "")?;
    let key_source = input::read(key_path)?;
    let key = PrivateKey::from_pem(&key_source.bytes, &key_source.name)?;
    // The first certificate is the identity's; the rest are its chain, as in PEM bundles.
    let first = certificates.remove(0).certificate;
    let others = certificates.into_iter().map(|c| c.certificate).collect();
    select(SourceKind::Pem, &certs.name, vec![(first, key)], others)
}

/// The card's C.AUT key, signing through the Konnektor's AuthSignatureService.
struct ConnectorKey {
    session: Session,
    handle: String,
    curve: Curve,
    /// The last failure, for the command to report as a Konnektor error.
    error: RefCell<Option<ti_connector_client::Error>>,
}

impl ConnectorKey {
    fn take_error(&self) -> Option<ti_connector_client::Error> {
        self.error.borrow_mut().take()
    }
}

impl JwsKey for ConnectorKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ES256
    }

    fn key_id(&self) -> Option<&str> {
        None
    }
}

impl signature::Signer<Signature> for ConnectorKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        // ExternalAuthenticate signs the hash as given: SHA-256 for ES256.
        let hash = Sha256::digest(msg);
        let auth = self.session.connector.auth();
        match block_on(auth.external_authenticate(&self.handle, &hash, SignatureType::Ecdsa)) {
            Ok(raw) if raw.len() == 64 => Ok(Signature::from(raw)),
            Ok(raw) => Err(signature::Error::from_source(format!(
                "Konnektor returned a {}-byte signature, expected 64",
                raw.len()
            ))),
            Err(error) => {
                let message = error.to_string();
                *self.error.borrow_mut() = Some(error);
                Err(signature::Error::from_source(message))
            }
        }
    }
}

/// The signer side of a [`ConnectorKey`] shared with the identity, so a failure can be
/// read back after `jws::sign` has turned it into a jwz error.
struct SharedConnectorKey(Rc<ConnectorKey>);

impl JwsKey for SharedConnectorKey {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }

    fn key_id(&self) -> Option<&str> {
        self.0.key_id()
    }
}

impl signature::Signer<Signature> for SharedConnectorKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        signature::Signer::try_sign(&*self.0, msg)
    }
}

/// The identity of `card` at the Konnektor `name` names (none: the selected one).
fn from_connector(
    name: Option<&str>,
    card: &str,
    global: &GlobalArgs,
    out: &Output,
) -> Result<Identity, CliError> {
    let args = ConnectorArgs::for_identity(name);
    let session = connector::open(&args, global, out)?;
    let found = block_on(session.connector.cards().find(card)).map_err(CliError::Connector)?;
    let certificates = session.connector.certificates();
    let read = block_on(certificates.read(&found.card_handle, Crypt::Ecc, &[CertRef::CAut]))
        .map_err(CliError::Connector)?;
    let label = format!(
        "{} card {}",
        session.name,
        found.iccsn.as_deref().unwrap_or(&found.card_handle)
    );
    let certificate = read
        .into_iter()
        .next()
        .map(|c| c.certificate)
        .ok_or_else(|| CliError::NoCertificate {
            source_name: format!("C.AUT ECC of {label}"),
        })?;
    if !is_aut(&certificate) {
        return Err(CliError::IdentityNotFound(format!(
            "{label}: C.AUT has no authentication key usage"
        )));
    }
    let curve = Curve::of_certificate(&certificate).ok_or_else(|| {
        CliError::KeyUnsupported(format!(
            "{label}: C.AUT key is not on brainpoolP256r1 or P-256"
        ))
    })?;
    let key = Rc::new(ConnectorKey {
        session,
        handle: found.card_handle.clone(),
        curve,
        error: RefCell::new(None),
    });
    Ok(Identity {
        kind: SourceKind::Connector,
        name: label,
        certificate,
        chain: Vec::new(),
        curve: key.curve,
        signer: Box::new(SharedConnectorKey(Rc::clone(&key))),
        connector: Some(key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/identity/").to_owned() + name,
        )
        .unwrap()
    }

    fn cert(name: &str) -> Certificate {
        ti_pki::parse_pem_certificates(&fixture(name))
            .unwrap()
            .remove(0)
    }

    #[test]
    fn aut_is_digital_signature_without_content_commitment() {
        assert!(is_aut(&cert("aut.pem")));
        assert!(!is_aut(&cert("osig.pem")), "OSIG carries contentCommitment");
        assert!(!is_aut(&cert("enc.pem")), "ENC has no digitalSignature");
        assert!(!is_aut(&cert("ca.pem")));
    }

    #[test]
    fn the_curve_is_read_from_the_certificate() {
        assert_eq!(
            Curve::of_certificate(&cert("aut.pem")),
            Some(Curve::Brainpool)
        );
    }

    #[test]
    fn a_card_alone_names_the_selected_connector() {
        use clap::Parser as _;
        let parse = |args: &[&str]| {
            crate::cli::Cli::try_parse_from(
                ["ti", "identity", "inspect"]
                    .iter()
                    .copied()
                    .chain(args.iter().copied()),
            )
        };
        let Ok(cli) = parse(&["--card", "SMC-B-7"]) else {
            panic!("--card alone is a source");
        };
        let crate::cli::Command::Identity(crate::cli::IdentityCommand::Inspect(args)) = cli.command
        else {
            panic!("identity inspect");
        };
        assert_eq!(args.card.as_deref(), Some("SMC-B-7"));
        assert!(args.connector.is_none(), "the selected Konnektor");
        assert!(
            parse(&["--connector", "praxis"]).is_err(),
            "a Konnektor needs a card"
        );
        assert!(parse(&[]).is_err(), "one source is required");
        assert!(
            parse(&["--p12", "a.p12", "--card", "x"]).is_err(),
            "one source only"
        );
    }

    #[test]
    fn a_key_signs_only_for_its_own_certificate() {
        let key = PrivateKey::from_pem(&fixture("aut.key"), "aut.key").unwrap();
        assert_eq!(key.curve, Curve::Brainpool);
        assert!(key.signer_for(&cert("aut.pem")).is_some());
        assert!(key.signer_for(&cert("osig.pem")).is_none());
    }
}
