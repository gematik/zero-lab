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

//! The sidecar's configuration, from its environment and the files it names: read here,
//! at the edge, and handed to the library typed.

use std::net::{SocketAddr, ToSocketAddrs as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use ti_hsm_proxy::{Iv, KeyKind, KeySpec};

const DEFAULT_SESSIONS: usize = 4;
const DEFAULT_WAIT: Duration = Duration::from_secs(2);
const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(5);

/// What the sidecar runs with.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// Where it listens (`HSM_PROXY_LISTEN_URL`, [`Listen`]).
    pub listen: Listen,
    /// The PKCS#11 module (`HSM_PROXY_PKCS11_MODULE_PATH`).
    pub module: PathBuf,
    /// The module's SHA-256 (`HSM_PROXY_PKCS11_MODULE_SHA256`, hex), checked before it is
    /// loaded (servers.md rule 7). Required outside the simulator mode.
    pub module_sha256: Option<[u8; 32]>,
    /// The token's label (`HSM_PROXY_TOKEN_LABEL`).
    pub token: String,
    /// The file holding the user PIN (`HSM_PROXY_USER_PIN_PATH`). Required outside the
    /// simulator mode, which uses a TEST-ONLY PIN.
    pub user_pin: Option<PathBuf>,
    /// The keys to serve (`HSM_PROXY_KEYS_PATH`, a JSON file).
    pub keys: Vec<KeySpec>,
    /// Sessions on the token (`HSM_PROXY_SESSIONS`, default 4).
    pub sessions: NonZeroUsize,
    /// How long a call waits for a free session (`HSM_PROXY_SESSION_WAIT_MS`, default 2000).
    pub wait: Duration,
    /// How often `grpc.health.v1` asks the token (`HSM_PROXY_HEALTH_INTERVAL_MS`, default
    /// 5000).
    pub health_interval: Duration,
    /// Where an AES-GCM IV comes from (`HSM_PROXY_GCM_IV`: `random` from C_GenerateRandom,
    /// `token` made by the token, as HSMs in FIPS mode do). Required outside the simulator
    /// mode, whose default is `random`, which SoftHSM2 needs.
    pub iv: Iv,
    /// The simulator mode (`HSM_PROXY_SIMULATOR=true`): the token is provisioned if it is
    /// not, with TEST-ONLY PINs, and missing keys are made. Only a build with the feature
    /// `simulator` has it.
    pub simulator: bool,
}

/// What is wrong with the configuration; it names the variable or file, never a secret.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(String);

fn error(message: impl Into<String>) -> ConfigError {
    ConfigError(message.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_id: String,
    kind: KindName,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum KindName {
    EcdsaP256,
    EcdsaP384,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

/// Reads the keys file: `{"keys": [{"key_id": "…", "kind": "ecdsa-p256"}, …]}`, with the
/// kinds `ecdsa-p256`, `ecdsa-p384` and `aes-256-gcm`.
pub fn parse_keys(json: &str) -> Result<Vec<KeySpec>, ConfigError> {
    let file: KeysFile =
        serde_json::from_str(json).map_err(|e| error(format!("HSM_PROXY_KEYS_PATH: {e}")))?;
    if file.keys.is_empty() {
        return Err(error("HSM_PROXY_KEYS_PATH: no keys"));
    }
    Ok(file
        .keys
        .into_iter()
        .map(|entry| KeySpec {
            key_id: entry.key_id,
            kind: match entry.kind {
                KindName::EcdsaP256 => KeyKind::EcdsaP256,
                KindName::EcdsaP384 => KeyKind::EcdsaP384,
                KindName::Aes256Gcm => KeyKind::Aes256Gcm,
            },
        })
        .collect())
}

fn parse_sha256(hex: &str) -> Result<[u8; 32], ConfigError> {
    let invalid = || error("HSM_PROXY_PKCS11_MODULE_SHA256: 64 hex digits");
    let hex = hex.trim();
    // from_str_radix takes a sign, so "+f" would pass for a pair: only hex digits are let in.
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

/// Where the sidecar listens (`HSM_PROXY_LISTEN_URL`, servers.md rule 29): the URL's scheme
/// is the mode.
#[derive(Debug, PartialEq, Eq)]
pub enum Listen {
    /// `unix:///path`: inside the pod.
    Unix(PathBuf),
    /// `https://host:port`: inside the cluster, the sidecar's own TLS from
    /// `HSM_PROXY_LISTEN_TLS_CERT_PATH` and `_KEY_PATH`; with `_CA_PATH` mTLS, admitting the
    /// identities of `_PEER_NAME`, a comma-separated list of DNS names or URIs.
    Tls {
        /// The address.
        address: SocketAddr,
        /// The certificate chain, PEM.
        cert: PathBuf,
        /// The private key, PEM.
        key: PathBuf,
        /// For mTLS: the client CA bundle and the identities admitted.
        clients: Option<(PathBuf, Vec<String>)>,
    },
    /// `http://host:port`: inside the cluster in plaintext, which only a mesh declared in
    /// `HSM_PROXY_LISTEN_MESH` may carry.
    Mesh {
        /// The address.
        address: SocketAddr,
        /// The mesh's name.
        mesh: String,
    },
}

/// The name of the Unix socket in the temporary directory that serves `grpc.health.v1` for
/// `hsm-proxy health` when the sidecar listens on TCP.
#[cfg_attr(
    not(feature = "grpc"),
    allow(dead_code, reason = "a transport's probe asks it; the tests do too")
)]
const PROBE_SOCKET: &str = "hsm-proxy-health.sock";

impl Listen {
    /// The Unix socket `hsm-proxy health` asks: the listener itself, or beside a TCP
    /// listener the health socket in the temporary directory (`TMPDIR`, rule 27).
    #[cfg_attr(
        not(feature = "grpc"),
        allow(dead_code, reason = "a transport's probe asks it; the tests do too")
    )]
    pub fn probe_socket(&self) -> PathBuf {
        match self {
            Listen::Unix(socket) => socket.clone(),
            Listen::Tls { .. } | Listen::Mesh { .. } => std::env::temp_dir().join(PROBE_SOCKET),
        }
    }
}

fn address(authority: &str) -> Result<SocketAddr, ConfigError> {
    let invalid = || error("HSM_PROXY_LISTEN_URL: a scheme, host and port, and no path");
    if authority.is_empty() || authority.contains('/') {
        return Err(invalid());
    }
    authority
        .to_socket_addrs()
        .map_err(|_| invalid())?
        .next()
        .ok_or_else(invalid)
}

/// Reads `HSM_PROXY_LISTEN_URL` and what its mode needs, and refuses what rule 17 refuses:
/// TLS settings beside plaintext, plaintext without a declared mesh, a mesh beside TLS, a
/// client CA without identities, identities without a client CA.
pub fn listen(var: impl Fn(&str) -> Option<String>) -> Result<Listen, ConfigError> {
    let url =
        var("HSM_PROXY_LISTEN_URL").ok_or_else(|| error("HSM_PROXY_LISTEN_URL is not set"))?;
    let tls_set = ["CERT_PATH", "KEY_PATH", "CA_PATH", "PEER_NAME"]
        .iter()
        .any(|suffix| var(&format!("HSM_PROXY_LISTEN_TLS_{suffix}")).is_some());
    let mesh = var("HSM_PROXY_LISTEN_MESH").filter(|mesh| !mesh.trim().is_empty());
    if let Some(path) = url.strip_prefix("unix://") {
        if !path.starts_with('/') {
            return Err(error("HSM_PROXY_LISTEN_URL: unix:///absolute/path"));
        }
        if tls_set || mesh.is_some() {
            return Err(error(
                "HSM_PROXY_LISTEN_TLS_* and HSM_PROXY_LISTEN_MESH are for a TCP listener, not a Unix socket",
            ));
        }
        return Ok(Listen::Unix(PathBuf::from(path)));
    }
    if let Some(authority) = url.strip_prefix("https://") {
        if mesh.is_some() {
            return Err(error(
                "HSM_PROXY_LISTEN_MESH is for http://; https:// is the sidecar's own TLS",
            ));
        }
        let path = |suffix: &str| {
            let name = format!("HSM_PROXY_LISTEN_TLS_{suffix}");
            var(&name)
                .map(PathBuf::from)
                .ok_or_else(|| error(format!("{name} is not set")))
        };
        let peers: Vec<String> = var("HSM_PROXY_LISTEN_TLS_PEER_NAME")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
        let clients = match (var("HSM_PROXY_LISTEN_TLS_CA_PATH"), peers.is_empty()) {
            (Some(ca), false) => Some((PathBuf::from(ca), peers)),
            (None, true) => None,
            (Some(_), true) => {
                return Err(error(
                    "HSM_PROXY_LISTEN_TLS_CA_PATH without HSM_PROXY_LISTEN_TLS_PEER_NAME: mTLS admits named identities only",
                ));
            }
            (None, false) => {
                return Err(error(
                    "HSM_PROXY_LISTEN_TLS_PEER_NAME without HSM_PROXY_LISTEN_TLS_CA_PATH",
                ));
            }
        };
        return Ok(Listen::Tls {
            address: address(authority)?,
            cert: path("CERT_PATH")?,
            key: path("KEY_PATH")?,
            clients,
        });
    }
    if let Some(authority) = url.strip_prefix("http://") {
        if tls_set {
            return Err(error("HSM_PROXY_LISTEN_TLS_* is for https://"));
        }
        let mesh = mesh.ok_or_else(|| {
            error("http:// inside the cluster needs the mesh that protects it in HSM_PROXY_LISTEN_MESH (servers.md rule 29)")
        })?;
        return Ok(Listen::Mesh {
            address: address(authority)?,
            mesh: mesh.trim().to_owned(),
        });
    }
    Err(error("HSM_PROXY_LISTEN_URL: unix://, https:// or http://"))
}

impl Config {
    /// Reads the configuration through `var` (the environment, in the binary) and the keys
    /// file through `read`.
    pub fn from_vars(
        var: impl Fn(&str) -> Option<String>,
        read: impl Fn(&Path) -> std::io::Result<String>,
    ) -> Result<Config, ConfigError> {
        let required = |name: &str| var(name).ok_or_else(|| error(format!("{name} is not set")));
        let simulator = match var("HSM_PROXY_SIMULATOR").as_deref() {
            None | Some("false") => false,
            Some("true") if cfg!(feature = "simulator") => true,
            Some("true") => {
                return Err(error(
                    "HSM_PROXY_SIMULATOR: this build has no simulator mode (feature simulator)",
                ));
            }
            Some(_) => return Err(error("HSM_PROXY_SIMULATOR: true or false")),
        };
        let listen = listen(&var)?;
        let module_sha256 = var("HSM_PROXY_PKCS11_MODULE_SHA256")
            .map(|hex| parse_sha256(&hex))
            .transpose()?;
        let user_pin = var("HSM_PROXY_USER_PIN_PATH").map(PathBuf::from);
        let iv = match var("HSM_PROXY_GCM_IV").as_deref() {
            Some("random") => Some(Iv::Random),
            Some("token") => Some(Iv::FromToken),
            Some(_) => return Err(error("HSM_PROXY_GCM_IV: random or token")),
            None => None,
        };
        if !simulator {
            if module_sha256.is_none() {
                return Err(error(
                    "HSM_PROXY_PKCS11_MODULE_SHA256 is not set: a vendor's module is loaded only by its hash",
                ));
            }
            if user_pin.is_none() {
                return Err(error("HSM_PROXY_USER_PIN_PATH is not set"));
            }
            if iv.is_none() {
                return Err(error(
                    "HSM_PROXY_GCM_IV is not set: random, or token for an HSM that makes the IV",
                ));
            }
        }
        let keys_path = PathBuf::from(required("HSM_PROXY_KEYS_PATH")?);
        let keys = read(&keys_path)
            .map_err(|e| error(format!("HSM_PROXY_KEYS_PATH {}: {e}", keys_path.display())))?;
        let sessions = match var("HSM_PROXY_SESSIONS") {
            None => NonZeroUsize::new(DEFAULT_SESSIONS),
            Some(n) => n.parse().ok(),
        }
        .ok_or_else(|| error("HSM_PROXY_SESSIONS: a number from 1"))?;
        let wait = match var("HSM_PROXY_SESSION_WAIT_MS") {
            None => DEFAULT_WAIT,
            Some(ms) => Duration::from_millis(
                ms.parse()
                    .map_err(|_| error("HSM_PROXY_SESSION_WAIT_MS: milliseconds"))?,
            ),
        };
        let health_interval = match var("HSM_PROXY_HEALTH_INTERVAL_MS") {
            None => DEFAULT_HEALTH_INTERVAL,
            Some(ms) => match ms.parse() {
                Ok(0) | Err(_) => {
                    return Err(error("HSM_PROXY_HEALTH_INTERVAL_MS: milliseconds from 1"));
                }
                Ok(ms) => Duration::from_millis(ms),
            },
        };
        Ok(Config {
            listen,
            health_interval,
            module: PathBuf::from(required("HSM_PROXY_PKCS11_MODULE_PATH")?),
            module_sha256,
            token: required("HSM_PROXY_TOKEN_LABEL")?,
            user_pin,
            keys: parse_keys(&keys)?,
            sessions,
            wait,
            iv: iv.unwrap_or(Iv::Random),
            simulator,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const KEYS: &str = r#"{"keys": [{"key_id": "pep-sig", "kind": "ecdsa-p256"}, {"key_id": "kek-v1", "kind": "aes-256-gcm"}]}"#;
    const SHA: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_vars(|name| vars.get(name).cloned(), |_| Ok(KEYS.to_owned()))
    }

    const VENDOR: &[(&str, &str)] = &[
        ("HSM_PROXY_LISTEN_URL", "unix:///run/hsm/proxy.sock"),
        ("HSM_PROXY_PKCS11_MODULE_PATH", "/opt/vendor/libpkcs11.so"),
        ("HSM_PROXY_PKCS11_MODULE_SHA256", SHA),
        ("HSM_PROXY_TOKEN_LABEL", "zeta"),
        ("HSM_PROXY_USER_PIN_PATH", "/run/secrets/pin"),
        ("HSM_PROXY_KEYS_PATH", "/etc/hsm-proxy/keys.json"),
        ("HSM_PROXY_GCM_IV", "token"),
    ];

    /// servers.md rule 7: a vendor's module is loaded only with its SHA-256 pinned, and
    /// the PIN comes from a file; the simulator mode is off unless asked for.
    #[test]
    fn servers_rule_7_a_vendor_module_needs_its_hash_a_pin_file_and_an_iv_source() {
        let config = config(VENDOR).unwrap();
        assert_eq!(
            config.listen,
            Listen::Unix(PathBuf::from("/run/hsm/proxy.sock"))
        );
        assert_eq!(config.module_sha256.unwrap()[1], 0x11);
        assert_eq!(config.iv, Iv::FromToken);
        assert!(!config.simulator);
        assert_eq!(config.sessions.get(), 4);
        assert_eq!(config.keys.len(), 2);
        for missing in [
            "HSM_PROXY_PKCS11_MODULE_SHA256",
            "HSM_PROXY_USER_PIN_PATH",
            "HSM_PROXY_GCM_IV",
        ] {
            let vars: Vec<_> = VENDOR
                .iter()
                .copied()
                .filter(|(k, _)| *k != missing)
                .collect();
            let refused = super::tests::config(&vars).unwrap_err();
            assert!(refused.0.contains(missing), "{refused}");
        }
    }

    /// TASK-389 #3: the simulator mode starts with no PIN file, no hash and no IV source.
    #[cfg(feature = "simulator")]
    #[test]
    fn task_389_3_the_simulator_mode_needs_no_pin_hash_or_iv() {
        let config = config(&[
            ("HSM_PROXY_SIMULATOR", "true"),
            ("HSM_PROXY_LISTEN_URL", "unix:///tmp/hsm.sock"),
            (
                "HSM_PROXY_PKCS11_MODULE_PATH",
                "/opt/homebrew/lib/softhsm/libsofthsm2.so",
            ),
            ("HSM_PROXY_TOKEN_LABEL", "zeta"),
            ("HSM_PROXY_KEYS_PATH", "keys.json"),
        ])
        .unwrap();
        assert!(config.simulator);
        assert_eq!(config.iv, Iv::Random);
        assert_eq!(config.user_pin, None);
    }

    /// servers.md rule 17: a build without the feature `simulator` refuses the simulator
    /// mode, so a production image cannot be started as one.
    #[cfg(not(feature = "simulator"))]
    #[test]
    fn servers_rule_17_a_production_build_has_no_simulator_mode() {
        let mut vars = VENDOR.to_vec();
        vars.push(("HSM_PROXY_SIMULATOR", "true"));
        let refused = config(&vars).unwrap_err();
        assert!(refused.0.contains("feature simulator"), "{refused}");
    }

    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str);

    fn listen_of(vars: &[(&str, &str)]) -> Result<Listen, ConfigError> {
        let vars: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        listen(|name| vars.get(name).cloned())
    }

    /// servers.md rule 29: the listener is a URL whose scheme is the mode: a Unix socket at
    /// an absolute path, https:// with the sidecar's own TLS, or http:// with a declared
    /// mesh. Anything else is refused.
    #[test]
    fn servers_rule_29_the_listener_is_a_url_whose_scheme_is_the_mode() {
        for url in [
            "tcp://0.0.0.0:50051",
            "unix://relative.sock",
            "/run/hsm.sock",
            "https://0.0.0.0:50051/path",
            "https://0.0.0.0",
        ] {
            let mut vars = VENDOR.to_vec();
            vars[0] = ("HSM_PROXY_LISTEN_URL", url);
            assert!(config(&vars).is_err(), "{url}");
        }
        let mtls = listen_of(&[
            ("HSM_PROXY_LISTEN_URL", "https://127.0.0.1:50051"),
            ("HSM_PROXY_LISTEN_TLS_CERT_PATH", "/tls/cert.pem"),
            ("HSM_PROXY_LISTEN_TLS_KEY_PATH", "/tls/key.pem"),
            ("HSM_PROXY_LISTEN_TLS_CA_PATH", "/tls/ca.pem"),
            (
                "HSM_PROXY_LISTEN_TLS_PEER_NAME",
                "spiffe://zeta/pep, pdp.zeta.svc",
            ),
        ])
        .unwrap();
        let Listen::Tls {
            clients: Some((_, allow)),
            ..
        } = &mtls
        else {
            panic!("{mtls:?}");
        };
        assert_eq!(allow, &["spiffe://zeta/pep", "pdp.zeta.svc"]);
        let mesh = listen_of(&[
            ("HSM_PROXY_LISTEN_URL", "http://127.0.0.1:50051"),
            ("HSM_PROXY_LISTEN_MESH", "istio"),
        ])
        .unwrap();
        assert!(
            matches!(mesh, Listen::Mesh { ref mesh, .. } if mesh == "istio"),
            "{mesh:?}"
        );
        assert_ne!(mesh.probe_socket(), PathBuf::from("/run/hsm/proxy.sock"));
    }

    /// servers.md rules 17 and 29: inconsistent combinations do not start: plaintext in the
    /// cluster without a declared mesh, TLS settings beside plaintext or a Unix socket, a
    /// mesh beside the sidecar's own TLS, a client CA without identities and identities
    /// without a client CA.
    #[test]
    fn servers_rule_17_an_inconsistent_listener_does_not_start() {
        let tls = [
            ("HSM_PROXY_LISTEN_TLS_CERT_PATH", "/tls/cert.pem"),
            ("HSM_PROXY_LISTEN_TLS_KEY_PATH", "/tls/key.pem"),
        ];
        let cases: [Case<'_>; 6] = [
            ("http://127.0.0.1:1", vec![], "HSM_PROXY_LISTEN_MESH"),
            (
                "http://127.0.0.1:1",
                vec![("HSM_PROXY_LISTEN_MESH", "istio"), tls[0]],
                "for https",
            ),
            (
                "unix:///run/hsm.sock",
                vec![("HSM_PROXY_LISTEN_MESH", "istio")],
                "not a Unix socket",
            ),
            (
                "https://127.0.0.1:1",
                vec![tls[0], tls[1], ("HSM_PROXY_LISTEN_MESH", "istio")],
                "own TLS",
            ),
            (
                "https://127.0.0.1:1",
                vec![
                    tls[0],
                    tls[1],
                    ("HSM_PROXY_LISTEN_TLS_CA_PATH", "/tls/ca.pem"),
                ],
                "named identities",
            ),
            (
                "https://127.0.0.1:1",
                vec![tls[0], tls[1], ("HSM_PROXY_LISTEN_TLS_PEER_NAME", "a")],
                "without HSM_PROXY_LISTEN_TLS_CA_PATH",
            ),
        ];
        for (url, mut vars, says) in cases {
            vars.push(("HSM_PROXY_LISTEN_URL", url));
            let refused = listen_of(&vars).unwrap_err();
            assert!(refused.0.contains(says), "{url}: {refused}");
        }
    }

    /// TASK-389: a key's kind is stated, never guessed; an unknown kind or field is refused.
    #[test]
    fn task_389_the_keys_file_states_each_kind() {
        assert_eq!(parse_keys(KEYS).unwrap()[1].kind, KeyKind::Aes256Gcm);
        for bad in [
            r#"{"keys": []}"#,
            r#"{"keys": [{"key_id": "a", "kind": "rsa-2048"}]}"#,
            r#"{"keys": [{"key_id": "a", "kind": "ecdsa-p256", "curve": "p256"}]}"#,
            r#"{"keys": [{"key_id": "a"}]}"#,
        ] {
            assert!(parse_keys(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_module_hash_is_64_hex_digits() {
        assert!(parse_sha256(SHA).is_ok());
        for bad in [
            "",
            "00",
            &SHA[..63],
            &format!("{}g", &SHA[..63]),
            &format!("ä{}", &SHA[2..]),
            &"+f".repeat(32),
        ] {
            assert!(parse_sha256(bad).is_err(), "{bad}");
        }
    }
}
