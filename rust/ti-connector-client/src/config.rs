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

//! A `.kon` file as front ends show it: every field that is not secret, and for each
//! secret only where it is kept. A `.kon` file is itself a secret, so nothing here
//! carries a password, the PKCS#12 bytes or the comfort signature's user ID.

use core::fmt::Write as _;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use ti_pki::Certificate;
use ti_types::Timestamp;

use crate::dotkon::{Credentials, Dotkon};

/// The redacted view of a `.kon` file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfigView {
    /// The Konnektor's base URL.
    pub url: String,
    /// The TI environment the file states.
    pub env: Option<String>,
    /// Call context: Mandant.
    pub mandant_id: String,
    /// Call context: workplace.
    pub workplace_id: String,
    /// Call context: client system.
    pub client_system_id: String,
    /// Whether a user ID is set; never its value, which in a comfort signature session
    /// lets anyone with the same context sign without a PIN.
    pub user_id_set: bool,
    /// Service endpoints rewritten to the host of `url`.
    pub rewrite_service_endpoints: bool,
    /// The name the server certificate must carry, if not the host of `url`.
    pub expected_host: Option<String>,
    /// Any server certificate is accepted.
    pub insecure_skip_verify: bool,
    /// How the client authenticates.
    pub credentials: CredentialsView,
    /// The certificates trusted for the Konnektor's TLS.
    pub trust_store: Vec<TrustEntry>,
    /// The environment variables the file takes values from; never their values.
    pub variables: Vec<String>,
}

/// The credentials without their secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialsView {
    /// `basic`, `pkcs12` or `none`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The basic user name; not a secret.
    pub username: Option<String>,
    /// Where the password is kept.
    pub password: Secret,
    /// Where the PKCS#12 bytes are kept.
    pub data: Secret,
    /// The client certificate of `pkcs12` credentials.
    pub client_certificate: Option<ClientCertificate>,
}

/// Where a secret of the file is kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Secret {
    /// `plain` (in the file), `environment` (`${NAME}`) or `absent`.
    pub stored: &'static str,
    /// The variables it is taken from, for `environment`.
    pub variables: Vec<String>,
}

impl Secret {
    /// Whether the value is written in the file itself.
    pub fn is_plain(&self) -> bool {
        self.stored == "plain"
    }
}

/// The client certificate of `pkcs12` credentials, or why it cannot be read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClientCertificate {
    /// The certificate of the pair the transport uses, when the file can be read.
    pub certificate: Option<CertificateView>,
    /// The key algorithm, e.g. `ECDSA P-256`, `RSA 2048`.
    pub key: Option<String>,
    /// Whether the TLS stack can sign with that key (RSA, P-256, P-384).
    pub key_usable: bool,
    /// Certificates with their key in the file; the first is used.
    pub pairs: usize,
    /// How the file is encrypted, e.g. `PBES2 AES-256-CBC`, `PKCS#12 3DES`.
    pub encryption: Vec<String>,
    /// Why the file cannot be used.
    pub error: Option<String>,
}

impl ClientCertificate {
    /// Whether the file still uses the PKCS#12 PBEs of RFC 7292 (3DES, RC2).
    pub fn legacy_encryption(&self) -> bool {
        self.encryption.iter().any(|e| e.starts_with("PKCS#12"))
    }
}

/// A certificate, as far as a front end shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CertificateView {
    /// The subject DN.
    pub subject: String,
    /// The issuer DN.
    pub issuer: String,
    /// Start of validity, RFC 3339.
    pub not_before: String,
    /// End of validity, RFC 3339.
    pub not_after: String,
    /// SHA-256 of the DER encoding, upper-case hex pairs separated by colons.
    pub sha256: String,
    /// End of validity, seconds since the epoch, for comparisons.
    #[serde(skip)]
    pub expires: Timestamp,
}

impl CertificateView {
    /// The view of a parsed certificate.
    pub fn of(certificate: &Certificate) -> Self {
        CertificateView {
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            not_before: certificate.not_before().to_string(),
            not_after: certificate.not_after().to_string(),
            sha256: sha256(certificate.der()),
            expires: certificate.not_after(),
        }
    }
}

/// One certificate of the trust store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustEntry {
    /// `pin` (an end-entity certificate, accepted by equality) or `ca` (an anchor).
    pub role: &'static str,
    /// The certificate; `None` if it does not parse.
    pub certificate: Option<CertificateView>,
}

impl ConfigView {
    /// The view of `dotkon`, parsed from `json`, which tells where each secret is kept.
    pub fn new(dotkon: &Dotkon, json: &[u8]) -> Self {
        let raw: Value = serde_json::from_slice(json).unwrap_or(Value::Null);
        let field = |name: &str| secret(raw.pointer(&format!("/credentials/{name}")));
        let (username, client_certificate) = match &dotkon.credentials {
            Credentials::Basic { username, .. } => (Some(username.clone()), None),
            Credentials::Pkcs12 { data, password } => {
                (None, Some(client_certificate(data, password)))
            }
            Credentials::None => (None, None),
        };
        ConfigView {
            url: dotkon.url.clone(),
            env: dotkon.env.map(|e| e.to_string()),
            mandant_id: dotkon.mandant_id.clone(),
            workplace_id: dotkon.workplace_id.clone(),
            client_system_id: dotkon.client_system_id.clone(),
            user_id_set: dotkon.user_id.is_some(),
            rewrite_service_endpoints: dotkon.rewrite_service_endpoints,
            expected_host: dotkon.expected_host.clone(),
            insecure_skip_verify: dotkon.insecure_skip_verify,
            credentials: CredentialsView {
                kind: dotkon.credentials.kind(),
                username,
                password: field("password"),
                data: field("data"),
                client_certificate,
            },
            trust_store: dotkon
                .trust_store
                .iter()
                .map(|der| {
                    let certificate = Certificate::from_der(der).ok();
                    TrustEntry {
                        role: if certificate.as_ref().is_some_and(Certificate::is_ca) {
                            "ca"
                        } else {
                            "pin"
                        },
                        certificate: certificate.as_ref().map(CertificateView::of),
                    }
                })
                .collect(),
            variables: dotkon.variables.clone(),
        }
    }

    /// The secrets written in the file itself, by their JSON path.
    pub fn plain_secrets(&self) -> Vec<&'static str> {
        [
            ("credentials.password", &self.credentials.password),
            ("credentials.data", &self.credentials.data),
        ]
        .into_iter()
        .filter(|(_, secret)| secret.is_plain())
        .map(|(path, _)| path)
        .collect()
    }
}

/// Where the raw value of a secret field is kept: only the variable names of `${NAME}`,
/// never the text around them, which may be part of the secret.
fn secret(value: Option<&Value>) -> Secret {
    let text = value.and_then(Value::as_str).unwrap_or_default();
    if text.is_empty() {
        return Secret {
            stored: "absent",
            variables: Vec::new(),
        };
    }
    let mut variables = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else { break };
        variables.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    let stored = if variables.is_empty() {
        "plain"
    } else {
        "environment"
    };
    Secret { stored, variables }
}

/// The client certificate the transport would use: the first certificate with its key.
pub fn client_certificate(data: &[u8], password: &str) -> ClientCertificate {
    let mut view = ClientCertificate {
        certificate: None,
        key: None,
        key_usable: false,
        pairs: 0,
        encryption: Vec::new(),
        error: None,
    };
    let p12 = match ti_pkcs12::decode(data, password) {
        Ok(p12) => p12,
        Err(e) if e.is_wrong_password() => {
            view.error = Some("wrong password for credentials.data".into());
            return view;
        }
        Err(e) => {
            view.error = Some(format!("credentials.data is no usable PKCS#12 file: {e}"));
            return view;
        }
    };
    view.encryption = p12.encryption.iter().map(|e| e.algorithm.clone()).collect();
    let pairs = p12.pairs();
    view.pairs = pairs.len();
    let Some(pair) = pairs.first() else {
        view.error = Some("credentials.data holds no certificate with its private key".into());
        return view;
    };
    match Certificate::from_der(&p12.certificates[pair.certificate].der) {
        Ok(certificate) => {
            let (key, usable) = key_name(&certificate);
            view.key = Some(key);
            view.key_usable = usable;
            view.certificate = Some(CertificateView::of(&certificate));
        }
        Err(e) => view.error = Some(format!("the client certificate does not parse: {e}")),
    }
    view
}

/// The public key's algorithm (`ECDSA P-256`, `RSA 2048`), and whether ring, the TLS
/// stack's crypto, can sign with it: RSA, P-256 and P-384, not brainpool.
fn key_name(certificate: &Certificate) -> (String, bool) {
    let (_, name) = ti_pki::key::classify_key(certificate.public_key_info(), Timestamp(0));
    let usable = name.starts_with("RSA ") || name == "ECDSA P-256" || name == "ECDSA P-384";
    (name, usable)
}

/// SHA-256 of `der` as `AB:CD:…`.
pub fn sha256(der: &[u8]) -> String {
    let mut out = String::with_capacity(95);
    for (i, byte) in Sha256::digest(der).iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        write!(out, "{byte:02X}").expect("writing to a String cannot fail");
    }
    out
}
