//! Reading certificates from a file or stdin: PEM, DER or PKCS#12.

use std::io::Read;
use std::path::Path;

use ti_pki::Certificate;

use crate::error::CliError;

/// The bytes of a FILE argument, with a name for messages.
pub struct Source {
    /// The file name, or `<stdin>`.
    pub name: String,
    /// The raw content.
    pub bytes: Vec<u8>,
}

/// Reads `path`, or stdin for `-`. Bytes, not text: DER is binary.
pub fn read(path: &Path) -> Result<Source, CliError> {
    if path == Path::new("-") {
        let name = "<stdin>".to_owned();
        let mut bytes = Vec::new();
        return match std::io::stdin().lock().read_to_end(&mut bytes) {
            Ok(_) => Ok(Source { name, bytes }),
            Err(source) => Err(CliError::Read {
                source_name: name,
                source,
            }),
        };
    }
    let name = path.display().to_string();
    std::fs::read(path)
        .map(|bytes| Source {
            name: name.clone(),
            bytes,
        })
        .map_err(|source| CliError::Read {
            source_name: name,
            source,
        })
}

/// A certificate from the input, and whether the input also holds its private key.
pub struct Loaded {
    /// The certificate.
    pub certificate: Certificate,
    /// The input is a PKCS#12 file with this certificate's key.
    pub private_key: bool,
    /// Its bag in a PKCS#12 file: `friendlyName` and `localKeyId`.
    pub bag: Option<(Option<String>, Option<Vec<u8>>)>,
}

/// Everything read from an input.
pub struct Input {
    /// The certificates, those with their key first.
    pub certificates: Vec<Loaded>,
    /// The decoded file, when the input is PKCS#12; its certificates are in
    /// [`Input::certificates`] too.
    pub pkcs12: Option<ti_pkcs12::Pkcs12>,
}

/// The certificates in `source`: every CERTIFICATE block of a PEM file, one DER
/// certificate, or the certificates of a PKCS#12 file decoded with `p12_password`. Of a
/// PKCS#12 file, the certificates with their key come first: they are the identity, the
/// others its chain.
pub fn certificates(source: &Source, p12_password: &str) -> Result<Vec<Loaded>, CliError> {
    Ok(load(source, p12_password)?.certificates)
}

/// [`certificates`], and for PKCS#12 input the decoded file.
pub fn load(source: &Source, p12_password: &str) -> Result<Input, CliError> {
    let certificate_error = |error| CliError::Certificate {
        source_name: source.name.clone(),
        source: error,
    };
    let without_key = |certificate| Loaded {
        certificate,
        private_key: false,
        bag: None,
    };
    let mut pkcs12 = None;
    let certs: Vec<Loaded> = if ti_pkcs12::is_pkcs12(&source.bytes) {
        let p12 =
            ti_pkcs12::decode(&source.bytes, p12_password).map_err(|error| CliError::Pkcs12 {
                source_name: source.name.clone(),
                source: error,
            })?;
        let paired: Vec<usize> = p12.pairs().iter().map(|pair| pair.certificate).collect();
        let mut order: Vec<usize> = paired.clone();
        order.extend((0..p12.certificates.len()).filter(|i| !paired.contains(i)));
        let certs = order
            .into_iter()
            .map(|i| {
                let bag = &p12.certificates[i];
                Ok(Loaded {
                    certificate: Certificate::from_der(&bag.der).map_err(certificate_error)?,
                    private_key: paired.contains(&i),
                    bag: Some((bag.friendly_name.clone(), bag.local_key_id.clone())),
                })
            })
            .collect::<Result<_, CliError>>()?;
        pkcs12 = Some(p12);
        certs
    } else if source.bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        ti_pki::parse_pem_certificates(&source.bytes)
            .map_err(certificate_error)?
            .into_iter()
            .map(without_key)
            .collect()
    } else if source.bytes.is_empty() {
        Vec::new()
    } else {
        vec![without_key(
            Certificate::from_der(&source.bytes).map_err(certificate_error)?,
        )]
    };
    if certs.is_empty() {
        return Err(CliError::NoCertificate {
            source_name: source.name.clone(),
        });
    }
    Ok(Input {
        certificates: certs,
        pkcs12,
    })
}
