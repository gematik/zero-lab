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

//! Writing `.kon` files, for the front ends that create and change them: the address
//! as a user types it, a new file from its parts, one field at a time, new credentials
//! or a new pin, and the rules a change must keep. Pure functions over the file's JSON;
//! reading, writing and asking are the host's.
//!
//! Konnektors are reached over https only. A change must not bring into a file for the
//! production environment (`env: pu`) what is not allowed there: `insecureSkipVerify`,
//! credentials of type `none` ([`refusals`]). What a file already has is left for the
//! user to fix.

use serde::Serialize;
use serde_json::{Map, Value};
use ti_pki::Certificate;

use crate::dotkon::{Credentials, Dotkon, DotkonError};

/// Why an address cannot be a Konnektor's url.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("address {input:?}: {reason}")]
pub struct AddressError {
    /// The address as given.
    pub input: String,
    /// What is wrong with it.
    pub reason: &'static str,
}

/// The url of a Konnektor from an address as a user types it: an https URL, a host
/// name, an IPv4 or IPv6 address, each with or without a port, and a path that is
/// dropped. It is always `https`; the port is kept as given.
///
/// # Errors
///
/// [`AddressError`] for another scheme (http too: the service directory is read over
/// https only), an empty host, a bad port or brackets that do not close.
pub fn normalize_address(input: &str) -> Result<String, AddressError> {
    let error = |reason| AddressError {
        input: input.to_owned(),
        reason,
    };
    let text = input.trim();
    let rest = match text.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
        Some(_) => {
            return Err(error(
                "the scheme must be https: the Konnektor is reached over TLS only",
            ));
        }
        None => text,
    };
    // A bare IPv6 address has more than one colon and no brackets; it carries no port.
    let bare_ipv6 = !rest.starts_with('[') && rest.matches(':').count() > 1;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(error("user information is not allowed"));
    }
    let (host, port) = if bare_ipv6 {
        (format!("[{authority}]"), None)
    } else if let Some(inner) = authority.strip_prefix('[') {
        let (address, after) = inner
            .split_once(']')
            .ok_or_else(|| error("an IPv6 address needs its closing ]"))?;
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| error("only :PORT may follow an IPv6 address"))?,
            ),
        };
        (format!("[{address}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (authority.to_owned(), None),
        }
    };
    if host.is_empty() || host == "[]" {
        return Err(error("the host is missing"));
    }
    if host.chars().any(char::is_whitespace) {
        return Err(error("the host contains a space"));
    }
    match port {
        None => Ok(format!("https://{host}")),
        Some(port) => match port.parse::<u16>() {
            Ok(0) | Err(_) => Err(error("the port must be a number from 1 to 65535")),
            Ok(port) => Ok(format!("https://{host}:{port}")),
        },
    }
}

/// `json` parsed with every `${NAME}` set, so a file is judged without the environment
/// it will run in.
///
/// # Errors
///
/// [`DotkonError`] for a file that is not a valid configuration.
pub fn validate(json: &[u8]) -> Result<Dotkon, DotkonError> {
    Dotkon::parse_with(json, |_| Some("MA==".to_owned()))
}

/// The server certificates pinned in `dotkon`'s trust store: its entries other than CA
/// certificates, which pin an issuer rather than the Konnektor.
pub fn pins(dotkon: &Dotkon) -> Vec<Vec<u8>> {
    dotkon
        .trust_store
        .iter()
        .filter(|der| !Certificate::from_der(der).is_ok_and(|c| c.is_ca()))
        .cloned()
        .collect()
}

/// What a change brings into a file that is not allowed: an http url anywhere, and for
/// the production environment insecureSkipVerify and credentials of type none. Only the
/// problems of `after` that `before` (the file before the change, `None` for a new one)
/// did not have.
pub fn refusals(before: Option<&Dotkon>, after: &Dotkon) -> Vec<String> {
    let problems = |dotkon: &Dotkon| -> Vec<&'static str> {
        let mut problems = Vec::new();
        if !crate::check::is_https(dotkon) {
            problems
                .push("an http url is not allowed: the service directory is read over https only");
        }
        if !dotkon.env.is_some_and(ti_types::Env::is_prod) {
            return problems;
        }
        if dotkon.insecure_skip_verify {
            problems
                .push("insecureSkipVerify is not allowed in the production environment (env pu)");
        }
        if dotkon.credentials == Credentials::None {
            problems.push(
                "credentials of type none are not allowed in the production environment (env pu)",
            );
        }
        problems
    };
    let had = before.map(problems).unwrap_or_default();
    problems(after)
        .into_iter()
        .filter(|p| !had.contains(p))
        .map(str::to_owned)
        .collect()
}

/// The credentials of a new or changed file.
#[derive(Clone, PartialEq, Eq)]
pub enum NewCredentials {
    /// HTTP basic authentication.
    Basic {
        /// User name.
        username: String,
        /// Password.
        password: String,
    },
    /// Mutual TLS with a PKCS#12 file.
    Pkcs12 {
        /// The file's bytes.
        data: Vec<u8>,
        /// Its password.
        password: String,
    },
    /// No client authentication.
    None,
}

impl core::fmt::Debug for NewCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            NewCredentials::Basic { .. } => "Basic",
            NewCredentials::Pkcs12 { .. } => "Pkcs12",
            NewCredentials::None => "None",
        })
    }
}

impl NewCredentials {
    fn to_value(&self) -> Value {
        let b64 = |bytes: &[u8]| crate::b64::encode(bytes);
        match self {
            NewCredentials::Basic { username, password } => serde_json::json!({
                "type": "basic", "username": username, "password": password,
            }),
            NewCredentials::Pkcs12 { data, password } => serde_json::json!({
                "type": "pkcs12", "data": b64(data), "password": password,
            }),
            NewCredentials::None => serde_json::json!({ "type": "none" }),
        }
    }
}

/// A new `.kon` file from its parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewConfig {
    /// The url, as [`normalize_address`] gives it.
    pub url: String,
    /// `ru`, `tu` or `pu`, if known.
    pub env: Option<String>,
    /// Call context: Mandant.
    pub mandant_id: String,
    /// Call context: client system.
    pub client_system_id: String,
    /// Call context: workplace.
    pub workplace_id: String,
    /// Call context: user, for calls that need one.
    pub user_id: Option<String>,
    /// How the client authenticates.
    pub credentials: NewCredentials,
    /// DER certificates trusted for the Konnektor's TLS: pins and CAs.
    pub trust_store: Vec<Vec<u8>>,
    /// Accept any server certificate.
    pub insecure_skip_verify: bool,
    /// The name the server certificate must carry, if not the host of `url`.
    pub expected_host: Option<String>,
    /// Send every service to the host of `url`.
    pub rewrite_service_endpoints: bool,
}

/// The file as written, its members in the order people read them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct File<'a> {
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<&'a str>,
    mandant_id: &'a str,
    client_system_id: &'a str,
    workplace_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<&'a str>,
    credentials: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    trust_store: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_host: Option<&'a str>,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    rewrite_service_endpoints: bool,
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    insecure_skip_verify: bool,
}

impl NewConfig {
    /// The file's JSON, pretty-printed with a final newline.
    pub fn to_json(&self) -> Vec<u8> {
        let file = File {
            url: &self.url,
            env: self.env.as_deref(),
            mandant_id: &self.mandant_id,
            client_system_id: &self.client_system_id,
            workplace_id: &self.workplace_id,
            user_id: self.user_id.as_deref(),
            credentials: self.credentials.to_value(),
            trust_store: self.trust_store.iter().map(|der| b64(der)).collect(),
            expected_host: self.expected_host.as_deref(),
            rewrite_service_endpoints: self.rewrite_service_endpoints,
            insecure_skip_verify: self.insecure_skip_verify,
        };
        pretty(&file)
    }
}

fn b64(bytes: &[u8]) -> String {
    crate::b64::encode(bytes)
}

fn pretty(value: &impl Serialize) -> Vec<u8> {
    let mut json = serde_json::to_vec_pretty(value).expect("JSON values serialize");
    json.push(b'\n');
    json
}

/// The members `set` may change: none of them a secret, since values on a command line
/// end up in shell histories and process lists.
pub const SETTABLE: [&str; 9] = [
    "url",
    "env",
    "mandantId",
    "clientSystemId",
    "workplaceId",
    "userId",
    "expectedHost",
    "rewriteServiceEndpoints",
    "insecureSkipVerify",
];

/// `json` with member `key` set to `value`; an empty value removes an optional member.
/// `url` goes through [`normalize_address`], the two switches take `true` or `false`.
///
/// # Errors
///
/// What is wrong with the key or the value.
pub fn set(json: &[u8], key: &str, value: &str) -> Result<Vec<u8>, String> {
    if !SETTABLE.contains(&key) {
        return Err(if key.starts_with("credentials") {
            format!(
                "{key} is a secret: change credentials with their own options, never on the command line"
            )
        } else {
            format!("{key} cannot be set; settable: {}", SETTABLE.join(", "))
        });
    }
    let mut file = object(json)?;
    let value = match key {
        "url" => Value::String(normalize_address(value).map_err(|e| e.to_string())?),
        "rewriteServiceEndpoints" | "insecureSkipVerify" => match value {
            "true" => Value::Bool(true),
            "false" | "" => Value::Bool(false),
            _ => return Err(format!("{key} takes true or false")),
        },
        _ if value.is_empty() => {
            file.remove(key);
            return Ok(pretty(&file));
        }
        _ => Value::String(value.to_owned()),
    };
    if value == Value::Bool(false) {
        file.remove(key);
    } else {
        file.insert(key.to_owned(), value);
    }
    Ok(pretty(&file))
}

/// `json` with `credentials` replaced.
///
/// # Errors
///
/// When `json` is not a JSON object.
pub fn with_credentials(json: &[u8], credentials: &NewCredentials) -> Result<Vec<u8>, String> {
    let mut file = object(json)?;
    file.insert("credentials".into(), credentials.to_value());
    Ok(pretty(&file))
}

/// `json` with `pin` as the only pin of `trustStore`; its CA certificates stay.
///
/// # Errors
///
/// When `json` is not a JSON object.
pub fn with_pin(json: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    let mut file = object(json)?;
    let mut store: Vec<Value> = file
        .get("trustStore")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            entry
                .as_str()
                .and_then(|text| crate::b64::decode(text).ok())
                .and_then(|der| Certificate::from_der(&der).ok())
                .is_some_and(|c| c.is_ca())
        })
        .cloned()
        .collect();
    store.insert(0, Value::String(b64(pin)));
    file.insert("trustStore".into(), Value::Array(store));
    Ok(pretty(&file))
}

fn object(json: &[u8]) -> Result<Map<String, Value>, String> {
    match serde_json::from_slice(json) {
        Ok(Value::Object(file)) => Ok(file),
        Ok(_) => Err("the .kon file is not a JSON object".into()),
        Err(e) => Err(format!("the .kon file is not JSON: {e}")),
    }
}
