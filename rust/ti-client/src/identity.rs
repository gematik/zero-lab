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

//! The SMC-B or HBA authentication identity (AUT): a certificate with digitalSignature
//! and without contentCommitment, and the key that signs for it. From a PKCS#12 file, a
//! PEM certificate and key, or a card at the Konnektor; the operations see one
//! [`Identity`] whichever it was, and ask it for a signer under the algorithm an
//! interface wants: `ES256` (ePA) or `BP256R1` (the IDP-Dienst), the same ECDSA-SHA256
//! under two names.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use der::Decode as _;
use der::asn1::ObjectIdentifier;
use jwz::crypto::CryptoError;
use jwz::crypto::asynchronous::BoxFuture;
use jwz::crypto::rustcrypto::RustCrypto;
use jwz::header::HeaderParams;
use jwz::jwa::SignatureAlgorithm;
use jwz::jwk::{EcKey, Jwk, KeyMaterial, Secret};
use jwz::keys::{AsyncSigner, JwsKey, Signature, Signer, SoftwareKey};
use sha2::{Digest, Sha256};
use ti_connector_client::types::{CertRef, Crypt};
use ti_connector_client::{ComfortUserId, Connector, SignatureType, Transport};
use ti_jwz::brainpool::BrainpoolEs256Key;
use ti_pki::Certificate;
use ti_pki::cert_type::is_authentication;
use zeroize::Zeroizing;

use crate::block_on;
use crate::connector;
use crate::connector::session::call;
use crate::error::Error;

const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const BRAINPOOL_P256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The curves an SMC-B or HBA authentication key is on (gemSpec_Krypt).
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
    pub fn of_certificate(cert: &Certificate) -> Option<Curve> {
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

    /// Whether a key on this curve signs `alg`: `ES256` on either, `BP256R1` on
    /// brainpool only.
    fn signs(self, alg: SignatureAlgorithm) -> bool {
        alg == SignatureAlgorithm::ES256
            || (alg == ti_jwz::brainpool::BP256R1 && self == Curve::Brainpool)
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

/// The identity: its certificate, the certificates found with it, and its key.
pub struct Identity {
    /// Where it came from.
    pub kind: SourceKind,
    /// The file, or, for a card, what the caller names it by.
    pub name: String,
    /// The AUT certificate.
    pub certificate: Certificate,
    /// The other certificates of the source (CAs), chain candidates.
    pub chain: Vec<Certificate>,
    /// The key's curve.
    pub curve: Curve,
    key: Key,
}

/// Where the private key is.
enum Key {
    /// In this process, decoded from the source.
    Soft(PrivateKey),
    /// On the card; the Konnektor signs.
    Connector(Rc<dyn CardKey>),
}

impl Identity {
    /// The AUT identity of a PKCS#12 file, `bytes`, which `name` names, opened with
    /// `password`.
    ///
    /// # Errors
    ///
    /// [`Error::Pkcs12`] for a file that does not open, [`Error::Certificate`] for a
    /// certificate that does not parse, [`Error::IdentityNotFound`] when no AUT
    /// certificate with its key is there, [`Error::KeyUnsupported`] for a key that is not
    /// ECDSA on brainpoolP256r1 or P-256.
    pub fn from_p12(bytes: &[u8], name: &str, password: &str) -> Result<Identity, Error> {
        let p12 = ti_pkcs12::decode(bytes, password).map_err(|error| Error::Pkcs12 {
            source_name: name.to_owned(),
            source: error,
        })?;
        let certificate_error = |error| Error::Certificate {
            source_name: name.to_owned(),
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
        select(SourceKind::P12, name, candidates, others)
    }

    /// The AUT identity of `certificates`, read from the file `name` names, and the PEM
    /// key `key`, read from the file `key_name` names: the first certificate is the
    /// identity's, the rest its chain, as in PEM bundles.
    ///
    /// # Errors
    ///
    /// [`Error::NoCertificate`] without certificates, [`Error::KeyUnsupported`] for a key
    /// that is not ECDSA on brainpoolP256r1 or P-256, [`Error::IdentityNotFound`] when it
    /// is not the first certificate's AUT key.
    pub fn from_pem(
        mut certificates: Vec<Certificate>,
        name: &str,
        key: &[u8],
        key_name: &str,
    ) -> Result<Identity, Error> {
        if certificates.is_empty() {
            return Err(Error::NoCertificate {
                source_name: name.to_owned(),
            });
        }
        let key = PrivateKey::from_pem(key, key_name)?;
        let first = certificates.remove(0);
        select(SourceKind::Pem, name, vec![(first, key)], certificates)
    }

    /// The identity of the card `identifier` names (a handle, an ICCSN or a Telematik-ID)
    /// at the Konnektor of `session`: its ECC C.AUT, which the card signs for as the user
    /// of its card session ([`connector::card_user`]). The identity keeps the Konnektor.
    ///
    /// # Errors
    ///
    /// [`Error::Connector`] when the card or its certificate cannot be read,
    /// [`Error::NoCertificate`] for a card without an ECC C.AUT, the errors of
    /// [`connector::card_user`], and those of a certificate that does not serve as an
    /// identity: [`Error::IdentityNotFound`] without the authentication key usage,
    /// [`Error::KeyUnsupported`] for a key that is not on brainpoolP256r1 or P-256.
    pub fn from_card<T: Transport + 'static>(
        session: connector::Session<T>,
        identifier: &str,
    ) -> Result<Identity, Error> {
        let found = connector::find(&session, identifier)?;
        let user = connector::card_user(&session, &found)?;
        let certificates = session.connector.certificates().as_user(user.as_ref());
        let read = call(certificates.read(&found.card_handle, Crypt::Ecc, &[CertRef::CAut]))?;
        let name = format!(
            "{} card {}",
            session.name,
            found.iccsn.as_deref().unwrap_or(&found.card_handle)
        );
        let certificate = read
            .into_iter()
            .next()
            .map(|c| c.certificate)
            .ok_or_else(|| Error::NoCertificate {
                source_name: format!("C.AUT ECC of {name}"),
            })?;
        Identity::on_card(
            name,
            certificate,
            session.connector,
            found.card_handle,
            user,
        )
    }

    /// The identity of a card's C.AUT `certificate`, which the card `handle` at the
    /// Konnektor `connector` signs for, as `user`; `name` names it.
    fn on_card<T: Transport + 'static>(
        name: String,
        certificate: Certificate,
        connector: Connector<T>,
        handle: String,
        user: Option<ComfortUserId>,
    ) -> Result<Identity, Error> {
        if !is_authentication(&certificate) {
            return Err(Error::IdentityNotFound(format!(
                "{name}: C.AUT has no authentication key usage"
            )));
        }
        let curve = Curve::of_certificate(&certificate).ok_or_else(|| {
            Error::KeyUnsupported(format!(
                "{name}: C.AUT key is not on brainpoolP256r1 or P-256"
            ))
        })?;
        Ok(Identity {
            kind: SourceKind::Connector,
            name,
            certificate,
            chain: Vec::new(),
            curve,
            key: Key::Connector(Rc::new(ConnectorKey {
                connector,
                handle,
                user,
                error: RefCell::new(None),
            })),
        })
    }

    /// The Telematik-ID: the admission statement's registration number.
    pub fn telematik_id(&self) -> Option<String> {
        self.certificate
            .admission()
            .ok()
            .flatten()
            .and_then(|a| a.registration_number)
    }

    /// A signer for `alg` with this identity's key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyUnsupported`] when the key's curve does not sign `alg` (`BP256R1`
    /// needs brainpoolP256r1).
    pub fn signer(&self, alg: SignatureAlgorithm) -> Result<Box<dyn AsyncSigner>, Error> {
        if !self.curve.signs(alg) {
            return Err(Error::KeyUnsupported(format!(
                "{}: a key on {} does not sign {}",
                self.name,
                self.curve.name(),
                alg.as_str()
            )));
        }
        match &self.key {
            Key::Soft(key) => Ok(Box::new(SoftSigner(
                key.signer_for(&self.certificate, alg)?,
            ))),
            Key::Connector(key) => Ok(Box::new(ConnectorSigner {
                key: Rc::clone(key),
                alg,
            })),
        }
    }

    /// `payload` as a compact JWS under `alg`: `x5c` the certificate, the rest from
    /// `params`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyUnsupported`] as [`Identity::signer`]; [`Error::Connector`]
    /// when the Konnektor refused to sign; [`Error::Signing`] otherwise.
    pub fn sign(
        &self,
        payload: &[u8],
        params: HeaderParams,
        alg: SignatureAlgorithm,
    ) -> Result<String, Error> {
        let signer = self.signer(alg)?;
        let params = params.x5c(&[self.certificate.der()]);
        block_on(jwz::jws::sign_async(payload, params, &*signer))
            .map_err(|error| self.signing_error(error))
    }

    /// A Konnektor's refusal as such, anything else as a signing failure.
    fn signing_error(&self, error: jwz::Error) -> Error {
        match &self.key {
            Key::Connector(key) => match key.take_error() {
                Some(connector) => Error::Connector(connector),
                None => Error::Signing(error.to_string()),
            },
            Key::Soft(_) => Error::Signing(error.to_string()),
        }
    }
}

/// A private key with its curve, as PKCS#8 or SEC1 encode it.
struct PrivateKey {
    curve: Curve,
    scalar: Zeroizing<Vec<u8>>,
}

impl PrivateKey {
    /// From PKCS#8 `PrivateKeyInfo` DER.
    fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, Error> {
        let info = pkcs8::PrivateKeyInfoRef::from_der(der)
            .map_err(|e| Error::KeyUnsupported(format!("not a PKCS#8 key: {e}")))?;
        if info.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(Error::KeyUnsupported(format!(
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
    fn from_sec1(der: &[u8], curve: Option<&ObjectIdentifier>) -> Result<PrivateKey, Error> {
        let key = sec1::EcPrivateKey::from_der(der)
            .map_err(|e| Error::KeyUnsupported(format!("not an EC private key: {e}")))?;
        let named = match key.parameters {
            Some(sec1::EcParameters::NamedCurve(oid)) => Some(oid),
            None => curve.copied(),
        };
        let oid =
            named.ok_or_else(|| Error::KeyUnsupported("EC key without a named curve".into()))?;
        let curve = Curve::from_oid(&oid).ok_or_else(|| {
            Error::KeyUnsupported(format!("curve {oid} is not brainpoolP256r1 or P-256"))
        })?;
        if key.private_key.len() != 32 {
            return Err(Error::KeyUnsupported(format!(
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
    fn from_pem(pem: &[u8], name: &str) -> Result<PrivateKey, Error> {
        let (label, der) = pem_rfc7468::decode_vec(pem)
            .map_err(|e| Error::KeyUnsupported(format!("{name}: {e}")))?;
        match label {
            "PRIVATE KEY" => Self::from_pkcs8(&der),
            "EC PRIVATE KEY" => Self::from_sec1(&der, None),
            "ENCRYPTED PRIVATE KEY" => Err(Error::KeyUnsupported(format!(
                "{name}: encrypted PKCS#8 keys are not supported; use a PKCS#12 file"
            ))),
            other => Err(Error::KeyUnsupported(format!(
                "{name}: a {other} block is not a private key"
            ))),
        }
    }

    /// The key as a private JWK on `cert`'s point: the constructors below refuse a
    /// scalar that does not belong to the point, which is how a key is matched to its
    /// certificate.
    fn jwk_on(&self, cert: &Certificate) -> Jwk {
        let mut material = EcKey::from_point(self.curve.crv(), cert.public_key());
        material.d = Some(Secret::new(self.scalar.to_vec()));
        Jwk::new(KeyMaterial::Ec(material))
    }

    /// Whether this is `cert`'s key.
    fn matches(&self, cert: &Certificate) -> bool {
        Curve::of_certificate(cert) == Some(self.curve)
            && self.signer_for(cert, SignatureAlgorithm::ES256).is_ok()
    }

    /// A signer for `alg` as `cert`'s key.
    fn signer_for(
        &self,
        cert: &Certificate,
        alg: SignatureAlgorithm,
    ) -> Result<Box<dyn Signer>, Error> {
        let jwk = self.jwk_on(cert);
        let mismatch = |e: jwz::Error| {
            Error::IdentityNotFound(format!("key does not match the certificate: {e}"))
        };
        if alg == SignatureAlgorithm::ES256 && self.curve == Curve::Brainpool {
            return Ok(Box::new(
                BrainpoolEs256Key::from_jwk(&jwk).map_err(mismatch)?,
            ));
        }
        let key = SoftwareKey::from_jwk(
            &jwk,
            alg,
            &ti_jwz::brainpool::registry(),
            Arc::new(ti_jwz::brainpool::backend(RustCrypto::new())),
        )
        .map_err(mismatch)?;
        Ok(Box::new(key))
    }
}

/// The AUT pair among `candidates` (certificates with a key each); `others` are the
/// chain.
fn select(
    kind: SourceKind,
    name: &str,
    candidates: Vec<(Certificate, PrivateKey)>,
    others: Vec<Certificate>,
) -> Result<Identity, Error> {
    let mut seen = Vec::new();
    // A sibling identity (OSIG, ENC) is not a chain candidate; only the CAs are.
    let chain = others;
    let mut found: Option<(Certificate, PrivateKey)> = None;
    for (cert, key) in candidates {
        if found.is_none() && is_authentication(&cert) {
            if key.matches(&cert) {
                found = Some((cert, key));
            } else {
                seen.push(format!("{} (key does not match)", cert.subject_cn()));
            }
        } else {
            seen.push(format!(
                "{} ({})",
                cert.subject_cn(),
                if is_authentication(&cert) {
                    "another AUT"
                } else {
                    "not an AUT key usage"
                }
            ));
        }
    }
    let Some((certificate, key)) = found else {
        let what = if seen.is_empty() {
            "no certificate with its key".to_owned()
        } else {
            format!("with their keys: {}", seen.join(", "))
        };
        return Err(Error::IdentityNotFound(format!("{name}: {what}")));
    };
    Ok(Identity {
        kind,
        name: name.to_owned(),
        certificate,
        chain,
        curve: key.curve,
        key: Key::Soft(key),
    })
}

/// A key on a card, whatever the Konnektor's transport.
trait CardKey {
    /// The signature over `msg`.
    fn sign<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, jwz::Error>>;

    /// The Konnektor's last refusal, once.
    fn take_error(&self) -> Option<ti_connector_client::Error>;
}

/// The card's C.AUT key at the Konnektor.
struct ConnectorKey<T> {
    connector: Connector<T>,
    handle: String,
    user: Option<ComfortUserId>,
    /// The last failure, for the caller to report as a Konnektor error.
    error: RefCell<Option<ti_connector_client::Error>>,
}

impl<T: Transport> CardKey for ConnectorKey<T> {
    fn sign<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, jwz::Error>> {
        Box::pin(self.external_authenticate(msg))
    }

    fn take_error(&self) -> Option<ti_connector_client::Error> {
        self.error.borrow_mut().take()
    }
}

impl<T: Transport> ConnectorKey<T> {
    /// ExternalAuthenticate over the SHA-256 of `msg`: the Konnektor signs the hash as
    /// given, raw r‖s comes back.
    async fn external_authenticate(&self, msg: &[u8]) -> Result<Signature, jwz::Error> {
        let hash = Sha256::digest(msg);
        let auth = self.connector.auth().as_user(self.user.as_ref());
        match auth
            .external_authenticate(&self.handle, &hash, SignatureType::Ecdsa)
            .await
        {
            Ok(raw) if raw.len() == 64 => Ok(Signature::from(raw)),
            // Not an r‖s pair on a 256-bit curve.
            Ok(_) => Err(CryptoError::Backend.into()),
            // The Konnektor's error is kept for the caller; jwz carries only a code.
            Err(error) => {
                *self.error.borrow_mut() = Some(error);
                Err(CryptoError::Backend.into())
            }
        }
    }
}

/// A [`CardKey`] under one JWS algorithm name: ECDSA-SHA256 either way.
struct ConnectorSigner {
    key: Rc<dyn CardKey>,
    alg: SignatureAlgorithm,
}

impl JwsKey for ConnectorSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.alg
    }

    fn key_id(&self) -> Option<&str> {
        None
    }
}

/// The card signs through the Konnektor's AuthSignatureService, a SOAP call the flow
/// awaits (private keys as functions, hardware-bound).
impl AsyncSigner for ConnectorSigner {
    fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, jwz::Error>> {
        self.key.sign(msg)
    }
}

/// A software key as the [`AsyncSigner`] every [`Signer`] is, behind one box type with
/// the card's signer.
struct SoftSigner(Box<dyn Signer>);

impl JwsKey for SoftSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }

    fn key_id(&self) -> Option<&str> {
        self.0.key_id()
    }
}

impl AsyncSigner for SoftSigner {
    fn sign_async<'a>(&'a self, msg: &'a [u8]) -> BoxFuture<'a, Result<Signature, jwz::Error>> {
        self.0.sign_async(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../ti-cli/tests/fixtures/identity/"
            )
            .to_owned()
                + name,
        )
        .unwrap()
    }

    fn cert(name: &str) -> Certificate {
        ti_pki::parse_pem_certificates(&fixture(name))
            .unwrap()
            .remove(0)
    }

    #[test]
    fn the_curve_is_read_from_the_certificate() {
        assert_eq!(
            Curve::of_certificate(&cert("aut.pem")),
            Some(Curve::Brainpool)
        );
    }

    #[test]
    fn a_key_signs_only_for_its_own_certificate_under_both_names() {
        let key = PrivateKey::from_pem(&fixture("aut.key"), "aut.key").unwrap();
        assert_eq!(key.curve, Curve::Brainpool);
        assert!(key.matches(&cert("aut.pem")));
        assert!(!key.matches(&cert("osig.pem")));
        let es256 = key
            .signer_for(&cert("aut.pem"), SignatureAlgorithm::ES256)
            .unwrap();
        assert_eq!(es256.algorithm(), SignatureAlgorithm::ES256);
        let bp = key
            .signer_for(&cert("aut.pem"), ti_jwz::brainpool::BP256R1)
            .unwrap();
        assert_eq!(bp.algorithm(), ti_jwz::brainpool::BP256R1);
        assert!(Curve::P256.signs(SignatureAlgorithm::ES256));
        assert!(!Curve::P256.signs(ti_jwz::brainpool::BP256R1));
    }
}
