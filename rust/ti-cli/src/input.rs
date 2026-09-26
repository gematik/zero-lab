//! Reading certificates from a file or stdin, PEM or DER.

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

/// The certificates in `source`: every CERTIFICATE block of a PEM file, or one DER
/// certificate.
pub fn certificates(source: &Source) -> Result<Vec<Certificate>, CliError> {
    let certificate_error = |error| CliError::Certificate {
        source_name: source.name.clone(),
        source: error,
    };
    let certs = if source.bytes.windows(11).any(|w| w == b"-----BEGIN ") {
        ti_pki::parse_pem_certificates(&source.bytes).map_err(certificate_error)?
    } else if source.bytes.is_empty() {
        Vec::new()
    } else {
        vec![Certificate::from_der(&source.bytes).map_err(certificate_error)?]
    };
    if certs.is_empty() {
        return Err(CliError::NoCertificate {
            source_name: source.name.clone(),
        });
    }
    Ok(certs)
}
