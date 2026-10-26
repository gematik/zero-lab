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

//! What can go wrong in a command, and the exit code each failure maps to.

use std::io;
use std::process::ExitCode;

/// The documented exit codes. Agents and scripts branch on these, so a code keeps its
/// meaning across versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// Success; for `verify`, the certificate is valid.
    Ok = 0,
    /// The certificate is not valid.
    Invalid = 1,
    /// Wrong arguments or options.
    Usage = 2,
    /// A remote party failed: trust material (roots.json, TSL) could not be obtained, or
    /// the Konnektor did not answer or refused the call.
    Remote = 3,
    /// An input file could not be read or holds no certificate.
    Input = 4,
    /// Output could not be written.
    Output = 5,
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        ExitCode::from(exit as u8)
    }
}

/// A failure that ends a command. Each carries a stable `kind` for JSON output and, where
/// the user can act on it, a hint.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// A file or stdin could not be read.
    #[error("cannot read {source_name}: {source}")]
    Read {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// The input holds no certificate.
    #[error("{source_name}: no certificate found")]
    NoCertificate {
        /// The file name, or `<stdin>`.
        source_name: String,
    },
    /// The input is not a readable certificate.
    #[error("{source_name}: {source}")]
    Certificate {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: ti_pki::Error,
    },
    /// A PKCS#12 file could not be opened.
    #[error("{source_name}: {source}")]
    Pkcs12 {
        /// The file name, or `<stdin>`.
        source_name: String,
        /// Why.
        #[source]
        source: ti_pkcs12::Error,
    },
    /// An output file exists and `--force` was not given.
    #[error("{0} exists")]
    OutputExists(String),
    /// `--env auto` found no evidence for production or test.
    #[error("cannot tell the TI environment from the certificates: {0}")]
    EnvironmentUndetected(String),
    /// The environment given does not fit the command.
    #[error("{0}")]
    Environment(String),
    /// Arguments that clap cannot reject alone: a combination the command needs.
    #[error("{0}")]
    Arguments(String),
    /// The trust material of the environment could not be used.
    #[error("trust material unavailable: {0}")]
    Trust(#[source] ti_pki::Error),
    /// roots.json or the TSL could not be loaded or failed verification.
    #[error("trust material unavailable: {0}")]
    TrustLoad(String),
    /// `ti schema` was asked for a command that has none.
    #[error("no JSON schema for {0:?}")]
    UnknownSchema(String),
    /// `pki verify --connect` could not reach the server or finish the handshake.
    #[error("{0}")]
    ServerUnreachable(String),
    /// The HTTP client could not be set up from the options.
    #[error("HTTP setup: {0}")]
    HttpSetup(String),
    /// No cache directory can be derived from the environment.
    #[error("cannot determine the cache directory: {0}")]
    CacheDir(&'static str),
    /// A profile's store failed with a result code of spec/store (STORE-129).
    #[error("{}", store_message(.profile, *.file, .path, .error))]
    Store {
        /// The profile.
        profile: String,
        /// Which of its files.
        file: StoreFile,
        /// The file's path, if there is one.
        path: String,
        /// The result code and what it is about.
        error: ti_store::store::StoreError,
    },
    /// No usable `.kon` file, or one the transport cannot use.
    #[error("{0}")]
    ConnectorConfig(String),
    /// A Konnektor call failed.
    #[error("Konnektor: {0}")]
    Connector(#[source] ti_connector_client::Error),
    /// The Konnektor refused a call for a card it restricts on its SOAP API.
    #[error("Konnektor, {card_type} card: {source}")]
    CardRestricted {
        /// The card type, e.g. `SMC-KT`.
        card_type: String,
        /// The Konnektor's answer.
        #[source]
        source: ti_connector_client::Error,
    },
    /// A PIN type that does not fit the card, or none where the card has two.
    #[error("{0}")]
    PinType(String),
    /// The source holds no authentication certificate together with its key.
    #[error("no AUT identity: {0}")]
    IdentityNotFound(String),
    /// A private key that is not ECDSA on brainpoolP256r1 or P-256.
    #[error("unsupported key: {0}")]
    KeyUnsupported(String),
    /// The claims to sign are not a JSON object.
    #[error("claims: {0}")]
    Claims(String),
    /// A header parameter jwz sets itself, or one that does not parse.
    #[error("header: {0}")]
    Header(String),
    /// Signing failed for a reason other than the Konnektor refusing.
    #[error("signing failed: {0}")]
    Signing(String),
    /// A signature file that is neither DER nor the curve's r‖s.
    #[error("signature: {0}")]
    SignatureMalformed(String),
    /// The IDP-Dienst flow failed: the IDP refused, did not answer, or answered
    /// outside the protocol.
    #[error("IDP-Dienst: {0}")]
    Idpd(#[source] ti_idpd::Error),
    /// The FHIR-Directory refused, did not answer, or answered outside the protocol;
    /// a failure of the IDP-Dienst flow inside it is reported as [`CliError::Idpd`].
    #[error("{0}")]
    Directory(#[source] Box<ti_directory::Error>),
    /// Writing to stdout failed.
    #[error("cannot write output: {0}")]
    Output(#[from] io::Error),
}

impl CliError {
    /// A stable, machine-readable name for the failure.
    pub fn kind(&self) -> &'static str {
        match self {
            CliError::Read { .. } => "input_unreadable",
            CliError::NoCertificate { .. } => "no_certificate",
            CliError::Certificate { .. } => "certificate_malformed",
            CliError::Pkcs12 { source, .. } if source.is_wrong_password() => "p12_password",
            CliError::Pkcs12 { .. } => "p12_unreadable",
            CliError::OutputExists(_) => "output_exists",
            CliError::EnvironmentUndetected(_) => "environment_undetected",
            CliError::Environment(_) => "environment_invalid",
            CliError::Arguments(_) => "arguments_invalid",
            CliError::Trust(_) | CliError::TrustLoad(_) => "trust_material_unavailable",
            CliError::HttpSetup(_) => "http_setup",
            CliError::ServerUnreachable(_) => "server_unreachable",
            CliError::UnknownSchema(_) => "unknown_schema",
            CliError::CacheDir(_) => "cache_dir_unknown",
            CliError::Store { error, .. } => store_kind(error.code()),
            CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => "connector_config",
            CliError::Connector(ti_connector_client::Error::Transport(_)) => {
                "connector_unreachable"
            }
            CliError::Connector(ti_connector_client::Error::Fault(_)) => "connector_fault",
            CliError::Connector(ti_connector_client::Error::Discovery(_)) => {
                "connector_unsupported"
            }
            CliError::Connector(_) => "connector_failed",
            CliError::CardRestricted { .. } => "card_restricted",
            CliError::PinType(_) => "pin_type",
            CliError::IdentityNotFound(_) => "identity_not_found",
            CliError::KeyUnsupported(_) => "key_unsupported",
            CliError::Claims(_) => "claims_invalid",
            CliError::Header(_) => "header_invalid",
            CliError::Signing(_) => "signing_failed",
            CliError::SignatureMalformed(_) => "signature_malformed",
            CliError::Idpd(ti_idpd::Error::Idp(_)) => "idpd_error",
            CliError::Idpd(ti_idpd::Error::Transport { .. }) => "idpd_unreachable",
            CliError::Idpd(ti_idpd::Error::Untrusted { .. }) => "idpd_untrusted",
            CliError::Idpd(_) => "idpd_protocol",
            CliError::Directory(error) => match **error {
                ti_directory::Error::Directory(_) => "directory_error",
                ti_directory::Error::AuthServer(_) => "directory_auth_server_error",
                ti_directory::Error::Transport { .. } => "directory_unreachable",
                _ => "directory_protocol",
            },
            CliError::Output(_) => "output_failed",
        }
    }

    /// What the user can do about it, if anything.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            CliError::Read { .. } => Some("check the path; use '-' to read from stdin"),
            CliError::NoCertificate { .. } | CliError::Certificate { .. } => {
                Some("expected PEM (-----BEGIN CERTIFICATE-----) or DER")
            }
            CliError::Pkcs12 { source, .. } if source.is_wrong_password() => {
                Some("pass the file's password with --p12-password (default 00)")
            }
            CliError::Pkcs12 { .. } => Some("expected a PKCS#12 (.p12, .pfx) file"),
            CliError::OutputExists(_) => {
                Some("choose another OUTPUT, or pass --force to replace it")
            }
            CliError::EnvironmentUndetected(_) | CliError::Environment(_) => {
                Some("pass --env prod, ref, test or dev")
            }
            CliError::TrustLoad(_) => {
                Some("check the network and the HTTP options (-v shows them), or pass --offline")
            }
            CliError::HttpSetup(_) => Some("check --cacert, --capath and --proxy"),
            CliError::ServerUnreachable(_) => Some(
                "check the host and port, the network and --proxy; or save the chain and pass it as FILE",
            ),
            CliError::UnknownSchema(_) => Some("the schema command without COMMAND lists them all"),
            CliError::CacheDir(_) => Some("set --cache-dir or TI_CACHE_DIR"),
            CliError::Store { file, error, .. } => store_hint(*file, error.code()),
            CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Some(
                "`connector configs` lists the configurations; select one with -c NAME or `connector use NAME`",
            ),
            CliError::Connector(ti_connector_client::Error::Transport(_)) => Some(
                "check the .kon url, the network and the Konnektor's TLS certificate (-v shows each call)",
            ),
            CliError::Connector(ti_connector_client::Error::Fault(fault)) => Some(
                fault
                    .trace
                    .iter()
                    .find_map(|t| t.code.and_then(fault_hint))
                    .unwrap_or("the Konnektor refused the call; its code and text say why"),
            ),
            CliError::CardRestricted { .. } => Some(
                "SMC-KT, KVK and eGK are restricted on the Konnektor's SOAP API; use an HBA or SMC-B",
            ),
            CliError::PinType(_) => Some("name the PIN: PIN.CH, PIN.QES or PIN.SMC"),
            CliError::IdentityNotFound(_) => Some(
                "the AUT certificate (digitalSignature, no contentCommitment) must be present together with its private key",
            ),
            CliError::KeyUnsupported(_) => Some(
                "identities sign with ECDSA on brainpoolP256r1 or P-256 (PKCS#8 or EC PRIVATE KEY)",
            ),
            CliError::Claims(_) => Some("pass the claims as a JSON object; '-' reads stdin"),
            CliError::Header(_) => {
                Some("alg, enc, crit, epk and zip are set by the tool; values are JSON or text")
            }
            CliError::SignatureMalformed(_) => {
                Some("expected a DER ECDSA-Sig-Value or r‖s of the curve's size (64 bytes)")
            }
            CliError::Idpd(ti_idpd::Error::Idp(_)) => Some(
                "the IDP refused; gematik_error_text says why (client_id, redirect_uri, an expired challenge, an unknown card)",
            ),
            CliError::Idpd(ti_idpd::Error::Transport { .. }) => {
                Some("check the network, --proxy and the IDP URL; -v shows each request")
            }
            CliError::Idpd(ti_idpd::Error::Untrusted { .. }) => Some(
                "the IDP's certificate is not valid in the environment's TSL (wrong --env, revoked, expired); `pki verify` explains, --idp-unverified skips the check",
            ),
            CliError::Idpd(_) => {
                Some("the IDP's answer departs from gemSpec_IDP_Dienst; -v shows the exchange")
            }
            CliError::Directory(error) => Some(match **error {
                ti_directory::Error::Directory(_) => {
                    "the FHIR-Directory refused; its message says why (an identity without an entry in the directory, a code it did not issue, a token it does not accept)"
                }
                ti_directory::Error::AuthServer(_) => {
                    "the directory's Keycloak refused the client credentials: check --client-id, the secret file and the endpoint (holder, service, ti-provider have their own realms)"
                }
                ti_directory::Error::Transport { .. } => {
                    "check the network, --proxy and the directory URL; -v shows each request"
                }
                _ => {
                    "the directory's answer departs from gemSpec_VZD_FHIR_Directory, or sends the identity to a foreign IDP; -v shows the exchange"
                }
            }),
            CliError::Trust(_)
            | CliError::Arguments(_)
            | CliError::Output(_)
            | CliError::Connector(_)
            | CliError::Signing(_) => None,
        }
    }

    /// The exit code the failure ends the process with.
    pub fn exit(&self) -> Exit {
        match self {
            CliError::Read { .. }
            | CliError::NoCertificate { .. }
            | CliError::Certificate { .. }
            | CliError::Pkcs12 { .. }
            | CliError::IdentityNotFound(_)
            | CliError::KeyUnsupported(_)
            | CliError::Claims(_)
            | CliError::SignatureMalformed(_) => Exit::Input,
            CliError::EnvironmentUndetected(_)
            | CliError::Environment(_)
            | CliError::Arguments(_)
            | CliError::OutputExists(_)
            | CliError::HttpSetup(_)
            | CliError::UnknownSchema(_)
            | CliError::CacheDir(_)
            | CliError::PinType(_)
            | CliError::Header(_)
            | CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Exit::Usage,
            CliError::Trust(_)
            | CliError::TrustLoad(_)
            | CliError::ServerUnreachable(_)
            | CliError::Connector(_)
            | CliError::CardRestricted { .. }
            | CliError::Signing(_)
            | CliError::Idpd(_)
            | CliError::Directory(_) => Exit::Remote,
            CliError::Output(_) => Exit::Output,
            CliError::Store { error, .. } => match error.code() {
                "busy" | "backend_error" => Exit::Output,
                _ => Exit::Usage,
            },
        }
    }

    /// Whether the reader of stdout went away (`ti … | head`), which is not an error.
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, CliError::Output(e) if e.kind() == io::ErrorKind::BrokenPipe)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        CliError::Output(error.into())
    }
}

/// What to do about a Konnektor fault, by its gematik error code. Most are about the
/// information model of gemSpec_Kon (Mandant, client system, workplace, card terminal),
/// which the Konnektor's administrator maintains and the `.kon` call context names.
fn fault_hint(code: i64) -> Option<&'static str> {
    Some(match code {
        4004 => {
            "the Konnektor does not know the .kon mandantId; compare it with the Mandanten in the Konnektor's information model"
        }
        4005 => {
            "the Konnektor does not know the .kon clientSystemId; compare it with the client systems in the Konnektor's information model"
        }
        4006 => {
            "the Konnektor does not know the .kon workplaceId; compare it with the workplaces in the Konnektor's information model"
        }
        4007 => {
            "the Konnektor does not know the card terminal (CtId); `connector get cards` lists the cards with their terminals"
        }
        4010 => {
            "the .kon clientSystemId is not assigned to its mandantId in the Konnektor's information model"
        }
        4011 => {
            "the .kon workplaceId is not assigned to its mandantId in the Konnektor's information model"
        }
        4012 => {
            "the card's terminal is not assigned to the .kon mandantId in the Konnektor's information model; `connector get cards` shows the terminal"
        }
        4021 => {
            "the call context is incomplete: the .kon needs mandantId, clientSystemId and workplaceId; some Konnektors answer 4021 for an ID they do not know as well, so compare all three with the Konnektor's information model"
        }
        4053 => {
            "PIN entry for an eGK needs a card terminal assigned locally to the .kon workplaceId; assign the eGK's terminal to that workplace in the Konnektor's information model (`connector get cards` shows the terminal)"
        }
        4060 => "the card terminal (PIN pad, display) is busy with another operation; retry",
        4092 => {
            "the card is in a terminal that is not local to the .kon workplaceId, and the workplace has no Remote-PIN-KT; in the Konnektor's information model assign that terminal locally to the workplace or name a Remote-PIN-KT for it, or use a workplaceId the terminal is local to (`connector get cards` shows the card's terminal)"
        }
        4093 => {
            "another client system holds the card in an exclusive session; retry once it is released"
        }
        4204 => {
            "the Konnektor could not authenticate the client system: check the .kon credentials (basic user and password, or the PKCS#12) against the client authentication configured in the Konnektor (ANCL_CAUT_MODE)"
        }
        4263 => {
            "comfort signature is switched off in the Konnektor; an administrator enables it in its management interface"
        }
        _ => return None,
    })
}

/// Which of a profile's files a store failure concerns, for its message and hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreFile {
    /// Resolving the profile: its name, directories, backend.
    Profile,
    /// The key file of the `key-file` wrapper.
    KeyFile,
    /// `keyring.bin`.
    Keyring,
    /// `state.db` or the state tree.
    StateDb,
    /// `cache.db` or the cache tree.
    CacheDb,
    /// One record.
    Record,
}

impl StoreFile {
    fn label(self) -> &'static str {
        match self {
            StoreFile::Profile => "",
            StoreFile::KeyFile => "key file ",
            StoreFile::Keyring => "keyring ",
            StoreFile::StateDb => "state ",
            StoreFile::CacheDb => "cache ",
            StoreFile::Record => "record ",
        }
    }
}

/// STORE-129: the profile, the file and the result code; never a payload.
fn store_message(
    profile: &str,
    file: StoreFile,
    path: &str,
    error: &ti_store::store::StoreError,
) -> String {
    let what = format!("{}{path}", file.label());
    let what = what.trim_end();
    let code = error.code();
    match (file, code) {
        (StoreFile::KeyFile, "not_found") => format!("profile {profile}: {what} not found"),
        (StoreFile::Profile, _) if what.is_empty() => format!("{code}: {error}"),
        _ if what.is_empty() => format!("profile {profile}: {code}: {error}"),
        _ => format!("profile {profile}: {what}: {code}: {error}"),
    }
}

fn store_kind(code: &str) -> &'static str {
    match code {
        "not_found" => "store_not_found",
        "expired" => "store_expired",
        "malformed" => "store_malformed",
        "unsupported_version" => "store_unsupported_version",
        "unknown_kid" => "store_unknown_kid",
        "auth_failed" => "store_auth_failed",
        "limit_exceeded" => "store_limit_exceeded",
        "invalid_argument" => "store_invalid_argument",
        "capability_missing" => "store_capability_missing",
        "no_keyring" => "store_no_keyring",
        "insecure_permissions" => "store_insecure_permissions",
        "busy" => "store_busy",
        _ => "store_backend_error",
    }
}

/// The hint table of spec/store section L.
fn store_hint(file: StoreFile, code: &str) -> Option<&'static str> {
    Some(match (file, code) {
        (_, "no_keyring") => "the profile has no keyring: run `ti profile create`",
        (StoreFile::KeyFile, "not_found") => {
            "set TI_STORE_KEK_PATH to the profile's key file; without it, `ti profile delete NAME` and log in again"
        }
        (StoreFile::KeyFile, "malformed") => {
            "the key file is not a store key: check TI_STORE_KEK_PATH, or run `ti profile rewrap` from a working key file"
        }
        (_, "insecure_permissions") => "run `chmod 600` on the key file",
        (StoreFile::Keyring, "auth_failed") => {
            "the key file does not belong to this profile's keyring: check TI_STORE_KEK_PATH; without the right key file, `ti profile delete NAME` and log in again"
        }
        (_, "auth_failed") => {
            "the record was altered or copied: run `ti store doctor --deep`, then `ti store rm`"
        }
        (_, "unsupported_version") => {
            "written by a newer tool: update ti, or use the newest tool installed"
        }
        (_, "busy") => {
            "another tool holds the database: wait for it, or find it with `ti store doctor`"
        }
        (_, "capability_missing") => {
            "the namespace needs the SQLite backend: unset TI_STORE_BACKEND"
        }
        (StoreFile::StateDb | StoreFile::Keyring, "malformed") => {
            "run `ti store doctor`; `ti profile delete NAME` starts over and loses the sealed records"
        }
        (StoreFile::Profile, "invalid_argument") => {
            "profile names are lowercase letters, digits and hyphens; TI_STATE_DIR and TI_CACHE_DIR are absolute; TI_STORE_BACKEND is sqlite or files"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ti_connector_client::{Error, Fault, TraceEntry};

    /// The hint of a fault whose trace carries `codes`, outermost first.
    fn hint(codes: &[i64]) -> &'static str {
        let trace = codes
            .iter()
            .map(|&code| TraceEntry {
                code: Some(code),
                error_text: None,
                error_type: None,
                severity: None,
                event_id: None,
                comp_type: None,
                detail: None,
            })
            .collect();
        CliError::Connector(Error::Fault(Fault {
            code: "soap:Server".into(),
            message: "fault".into(),
            trace,
        }))
        .hint()
        .unwrap()
    }

    fn names(hint: &str, words: &[&str]) {
        for word in words {
            assert!(hint.contains(word), "{word:?} missing in: {hint}");
        }
    }

    #[test]
    fn kon_4092_without_remote_pin_kt_hints_the_workplace() {
        names(
            hint(&[4092]),
            &["Remote-PIN-KT", "workplaceId", "connector get cards"],
        );
    }

    #[test]
    fn kon_4053_egk_at_a_remote_terminal_hints_the_workplace() {
        names(hint(&[4053]), &["eGK", "workplaceId"]);
    }

    #[test]
    fn kon_4004_to_4006_unknown_ids_name_their_kon_field() {
        names(hint(&[4004]), &["mandantId"]);
        names(hint(&[4005]), &["clientSystemId"]);
        names(hint(&[4006]), &["workplaceId"]);
        names(hint(&[4007]), &["CtId", "connector get cards"]);
    }

    #[test]
    fn kon_4010_to_4012_unassigned_ids_name_the_mandant() {
        names(hint(&[4010]), &["clientSystemId", "mandantId"]);
        names(hint(&[4011]), &["workplaceId", "mandantId"]);
        names(hint(&[4012]), &["terminal", "mandantId"]);
    }

    /// The Konnektor may report an unknown ID as 4021 too, so the hint names all three.
    #[test]
    fn kon_4021_incomplete_context_names_all_three_ids() {
        names(
            hint(&[4021]),
            &["mandantId", "clientSystemId", "workplaceId"],
        );
    }

    #[test]
    fn kon_4204_unauthenticated_client_system_hints_the_credentials() {
        names(hint(&[4204]), &["credentials", "ANCL_CAUT_MODE"]);
    }

    #[test]
    fn kon_4093_and_4060_busy_card_or_terminal_hint_a_retry() {
        names(hint(&[4093]), &["retry"]);
        names(hint(&[4060]), &["retry"]);
    }

    #[test]
    fn kon_4263_comfort_signature_off_hints_the_administrator() {
        names(hint(&[4263]), &["comfort signature", "administrator"]);
    }

    /// The first code of the trace with a hint wins; one without falls back.
    #[test]
    fn the_first_known_code_of_the_trace_decides() {
        names(hint(&[4000, 4092]), &["Remote-PIN-KT"]);
        assert_eq!(
            hint(&[4000]),
            "the Konnektor refused the call; its code and text say why"
        );
    }
}
