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

const TSL_ROLLBACK_HINT: &str = "an older list than the one kept from an earlier run was rejected; \
     it can be an attack or a mirror lagging behind, so find out why first (another network, the \
     proxy, -k). Only if the kept list is known to be wrong, remove tsl/ID.json in the state \
     directory; the check then restarts from the next verified TSL";

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
    /// A TSL verified but does not follow the one kept from an earlier run (TSLSIG-053).
    /// Its own variant for its hint: the network is not what to look at. The kind stays
    /// `trust_material_unavailable`, since the material cannot be used.
    #[error("trust material unavailable: {0}")]
    TslRollback(String),
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
    /// No state directory can be derived from the environment.
    #[error("cannot determine the state directory: {0}")]
    StateDir(&'static str),
    /// The download cache could not be read, written or cleared.
    #[error("cache {path}: {reason}")]
    Cache {
        /// The cache directory or file.
        path: String,
        /// What went wrong.
        reason: String,
    },
    /// A state file or directory, such as the TSL state or a comfort ID, could not be
    /// read, parsed or written.
    #[error("state file {path}: {reason}")]
    State {
        /// The file.
        path: String,
        /// What went wrong.
        reason: String,
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
    Idpd(#[source] ti_idpd_client::Error),
    /// The FHIR-Directory refused, did not answer, or answered outside the protocol;
    /// a failure of the IDP-Dienst flow inside it is reported as [`CliError::Idpd`].
    #[error("{0}")]
    Directory(#[source] Box<ti_directory_client::Error>),
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
            CliError::Trust(_) | CliError::TrustLoad(_) | CliError::TslRollback(_) => {
                "trust_material_unavailable"
            }
            CliError::HttpSetup(_) => "http_setup",
            CliError::ServerUnreachable(_) => "server_unreachable",
            CliError::UnknownSchema(_) => "unknown_schema",
            CliError::CacheDir(_) => "cache_dir_unknown",
            CliError::StateDir(_) => "state_dir_unknown",
            CliError::Cache { .. } => "cache_failed",
            CliError::State { .. } => "state_file_failed",
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
            CliError::Idpd(ti_idpd_client::Error::Idp(_)) => "idpd_error",
            CliError::Idpd(ti_idpd_client::Error::Transport { .. }) => "idpd_unreachable",
            CliError::Idpd(ti_idpd_client::Error::Untrusted { .. }) => "idpd_untrusted",
            CliError::Idpd(_) => "idpd_protocol",
            CliError::Directory(error) => match **error {
                ti_directory_client::Error::Directory(_) => "directory_error",
                ti_directory_client::Error::AuthServer(_) => "directory_auth_server_error",
                ti_directory_client::Error::Transport { .. } => "directory_unreachable",
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
            CliError::TrustLoad(_) => Some(
                "check the network and the HTTP options (-v shows them), or pass --offline; \
                     the TSL's signature is published only over plain HTTP, so port 80 to its \
                     download point must be open",
            ),
            CliError::TslRollback(_) => Some(TSL_ROLLBACK_HINT),
            CliError::HttpSetup(_) => Some("check --cacert, --capath and --proxy"),
            CliError::ServerUnreachable(_) => Some(
                "check the host and port, the network and --proxy; or save the chain and pass it as FILE",
            ),
            CliError::UnknownSchema(_) => Some("the schema command without COMMAND lists them all"),
            CliError::CacheDir(_) => Some("set --cache-dir or TI_CACHE_DIR"),
            CliError::StateDir(_) => Some("set TI_STATE_DIR"),
            CliError::Cache { .. } => {
                Some("the message names what failed; --cache-dir moves the cache")
            }
            CliError::State { .. } => Some("the message names the file"),
            CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Some(
                "`connector config list` shows the configurations; select one with -c NAME or `connector use NAME`",
            ),
            CliError::Connector(ti_connector_client::Error::Transport(_)) => Some(
                "`connector config test` finds the failing step, a refused client certificate too; -v shows each call",
            ),
            CliError::Connector(ti_connector_client::Error::Discovery(
                ti_connector_client::DiscoveryError::ForeignEndpoint { .. },
            )) => Some(ti_connector_client::check::FOREIGN_ENDPOINT),
            CliError::Connector(ti_connector_client::Error::Fault(fault)) => Some(
                fault
                    .hint()
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
            CliError::Idpd(ti_idpd_client::Error::Idp(_)) => Some(
                "the IDP refused; gematik_error_text says why (client_id, redirect_uri, an expired challenge, an unknown card)",
            ),
            CliError::Idpd(ti_idpd_client::Error::Transport { .. }) => {
                Some("check the network, --proxy and the IDP URL; -v shows each request")
            }
            CliError::Idpd(ti_idpd_client::Error::Untrusted { .. }) => Some(
                "the IDP's certificate is not valid in the environment's TSL (wrong --env, revoked, expired); `pki verify` explains, --idp-unverified skips the check",
            ),
            CliError::Idpd(_) => {
                Some("the IDP's answer departs from gemSpec_IDP_Dienst; -v shows the exchange")
            }
            CliError::Directory(error) => Some(match **error {
                ti_directory_client::Error::Directory(_) => {
                    "the FHIR-Directory refused; its message says why (an identity without an entry in the directory, a code it did not issue, a token it does not accept)"
                }
                ti_directory_client::Error::AuthServer(_) => {
                    "the directory's Keycloak refused the client credentials: check --client-id, the secret file and the endpoint (holder, service, ti-provider have their own realms)"
                }
                ti_directory_client::Error::Transport { .. } => {
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
            | CliError::StateDir(_)
            | CliError::PinType(_)
            | CliError::Header(_)
            | CliError::ConnectorConfig(_)
            | CliError::Connector(ti_connector_client::Error::Config(_)) => Exit::Usage,
            CliError::Trust(_)
            | CliError::TrustLoad(_)
            | CliError::TslRollback(_)
            | CliError::ServerUnreachable(_)
            | CliError::Connector(_)
            | CliError::CardRestricted { .. }
            | CliError::Signing(_)
            | CliError::Idpd(_)
            | CliError::Directory(_) => Exit::Remote,
            CliError::Output(_) | CliError::State { .. } | CliError::Cache { .. } => Exit::Output,
        }
    }

    /// Whether the reader of stdout went away (`ti … | head`), which is not an error.
    pub fn is_broken_pipe(&self) -> bool {
        matches!(self, CliError::Output(e) if e.kind() == io::ErrorKind::BrokenPipe)
    }
}

impl From<ti_client::Error> for CliError {
    fn from(error: ti_client::Error) -> Self {
        match error {
            ti_client::Error::Setup(message) => CliError::HttpSetup(message),
            ti_client::Error::Connector(error) => CliError::Connector(error),
            ti_client::Error::ConnectorConfig(message) => CliError::ConnectorConfig(message),
            ti_client::Error::CardRestricted { card_type, source } => {
                CliError::CardRestricted { card_type, source }
            }
            ti_client::Error::PinType(error) => CliError::PinType(error.to_string()),
            ti_client::Error::Refused(message) => CliError::Arguments(message),
            ti_client::Error::Write(error) => CliError::Output(error),
            ti_client::Error::NoCertificate { source_name } => {
                CliError::NoCertificate { source_name }
            }
            ti_client::Error::Certificate {
                source_name,
                source,
            } => CliError::Certificate {
                source_name,
                source,
            },
            ti_client::Error::Pkcs12 {
                source_name,
                source,
            } => CliError::Pkcs12 {
                source_name,
                source,
            },
            ti_client::Error::EnvironmentUndetected(message) => {
                CliError::EnvironmentUndetected(message)
            }
            ti_client::Error::Trust(error) => CliError::Trust(error),
            ti_client::Error::TrustLoad(message) => CliError::TrustLoad(message),
            ti_client::Error::TslRollback(message) => CliError::TslRollback(message),
            ti_client::Error::ServerUnreachable(message) => CliError::ServerUnreachable(message),
            ti_client::Error::Cache { path, reason } => CliError::Cache { path, reason },
            ti_client::Error::State { path, reason } => CliError::State { path, reason },
            ti_client::Error::IdentityNotFound(message) => CliError::IdentityNotFound(message),
            ti_client::Error::KeyUnsupported(message) => CliError::KeyUnsupported(message),
            ti_client::Error::Signing(message) => CliError::Signing(message),
            ti_client::Error::SignatureMalformed(message) => CliError::SignatureMalformed(message),
            ti_client::Error::Idpd(error) => CliError::Idpd(error),
            ti_client::Error::Directory(error) => CliError::Directory(error),
            error @ ti_client::Error::ProbeEndpoints(_) => {
                CliError::ConnectorConfig(error.to_string())
            }
            ti_client::Error::Randomness => {
                CliError::Output(io::Error::other("no system randomness"))
            }
        }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        CliError::Output(error.into())
    }
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
            &["Remote-PIN-KT", "workplaceId", "card list"],
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
        names(hint(&[4007]), &["CtId", "card list"]);
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

    /// TSLSIG-053: ti-client's rollback stays apart from a failed download, so its hint
    /// points at the kept list, not at the network.
    #[test]
    fn tslsig_053_a_rejected_older_list_hints_at_the_kept_state() {
        let error = CliError::from(ti_client::Error::TslRollback("tsl_id_incorrect".into()));
        assert_eq!(error.kind(), "trust_material_unavailable");
        let hint = error.hint().unwrap();
        assert!(hint.contains("older list"), "{hint}");
        assert!(hint.contains("tsl/ID.json"), "{hint}");
        assert!(!hint.contains("port 80"), "not a network problem: {hint}");
    }

    /// One error of every kind, in the order of [`CliError`]'s variants.
    fn every_kind() -> Vec<CliError> {
        let mut errors = local_kinds();
        errors.extend(remote_kinds());
        errors
    }

    fn local_kinds() -> Vec<CliError> {
        let pki = || ti_pki::Error::Malformed {
            what: "certificate",
            reason: "test".into(),
        };
        vec![
            CliError::Read {
                source_name: "a".into(),
                source: io::Error::other("test"),
            },
            CliError::NoCertificate {
                source_name: "a".into(),
            },
            CliError::Certificate {
                source_name: "a".into(),
                source: pki(),
            },
            CliError::Pkcs12 {
                source_name: "a".into(),
                source: ti_pkcs12::Error::MacMismatch,
            },
            CliError::Pkcs12 {
                source_name: "a".into(),
                source: ti_pkcs12::Error::Malformed {
                    what: "PFX",
                    reason: "test".into(),
                },
            },
            CliError::OutputExists("a".into()),
            CliError::EnvironmentUndetected("a".into()),
            CliError::Environment("a".into()),
            CliError::Arguments("a".into()),
            CliError::Trust(pki()),
            CliError::TrustLoad("a".into()),
            CliError::TslRollback("a".into()),
            CliError::UnknownSchema("a".into()),
            CliError::ServerUnreachable("a".into()),
            CliError::HttpSetup("a".into()),
            CliError::CacheDir("a"),
            CliError::StateDir("a"),
            CliError::Cache {
                path: "a".into(),
                reason: "a".into(),
            },
            CliError::State {
                path: "a".into(),
                reason: "a".into(),
            },
        ]
    }

    fn remote_kinds() -> Vec<CliError> {
        vec![
            CliError::ConnectorConfig("a".into()),
            CliError::Connector(Error::Transport(ti_connector_client::TransportError {
                message: "a".into(),
                timed_out: false,
            })),
            CliError::Connector(Error::Fault(Fault {
                code: "soap:Server".into(),
                message: "a".into(),
                trace: Vec::new(),
            })),
            CliError::Connector(Error::Discovery(
                ti_connector_client::DiscoveryError::NotAdvertised {
                    service: "a".into(),
                },
            )),
            CliError::Connector(Error::Decode("a".into())),
            CliError::CardRestricted {
                card_type: "EGK".into(),
                source: Error::Decode("a".into()),
            },
            CliError::PinType("a".into()),
            CliError::IdentityNotFound("a".into()),
            CliError::KeyUnsupported("a".into()),
            CliError::Claims("a".into()),
            CliError::Header("a".into()),
            CliError::Signing("a".into()),
            CliError::SignatureMalformed("a".into()),
            CliError::Idpd(ti_idpd_client::Error::Idp(
                ti_idpd_client::IdpError::default(),
            )),
            CliError::Idpd(ti_idpd_client::Error::Transport {
                what: "a",
                source: ti_idpd_client::http::TransportError("a".into()),
            }),
            CliError::Idpd(ti_idpd_client::Error::Untrusted {
                which: ti_idpd_client::trust::IdpCertificate::TokenSigner,
                detail: "a".into(),
            }),
            CliError::Idpd(ti_idpd_client::Error::Malformed {
                what: "a",
                detail: "a".into(),
            }),
            CliError::Directory(Box::new(ti_directory_client::Error::Directory(
                ti_directory_client::DirectoryError::default(),
            ))),
            CliError::Directory(Box::new(ti_directory_client::Error::AuthServer(
                ti_directory_client::OAuthError::default(),
            ))),
            CliError::Directory(Box::new(ti_directory_client::Error::Transport {
                what: "a",
                source: ti_directory_client::http::TransportError("a".into()),
            })),
            CliError::Directory(Box::new(ti_directory_client::Error::Malformed {
                what: "a",
                detail: "a".into(),
            })),
            CliError::Output(io::Error::other("a")),
        ]
    }

    /// Fails to compile when a variant is added, so that [`every_kind`] gets it too.
    fn has_a_sample(error: &CliError) {
        match error {
            CliError::Read { .. }
            | CliError::NoCertificate { .. }
            | CliError::Certificate { .. }
            | CliError::Pkcs12 { .. }
            | CliError::OutputExists(_)
            | CliError::EnvironmentUndetected(_)
            | CliError::Environment(_)
            | CliError::Arguments(_)
            | CliError::Trust(_)
            | CliError::TrustLoad(_)
            | CliError::TslRollback(_)
            | CliError::UnknownSchema(_)
            | CliError::ServerUnreachable(_)
            | CliError::HttpSetup(_)
            | CliError::CacheDir(_)
            | CliError::StateDir(_)
            | CliError::Cache { .. }
            | CliError::State { .. }
            | CliError::ConnectorConfig(_)
            | CliError::Connector(_)
            | CliError::CardRestricted { .. }
            | CliError::PinType(_)
            | CliError::IdentityNotFound(_)
            | CliError::KeyUnsupported(_)
            | CliError::Claims(_)
            | CliError::Header(_)
            | CliError::Signing(_)
            | CliError::SignatureMalformed(_)
            | CliError::Idpd(_)
            | CliError::Directory(_)
            | CliError::Output(_) => {}
        }
    }

    /// AGENTS.md, which `ti agent` prints, names every error kind with its exit code,
    /// and only those (docs/conventions/agents.md: the guide matches the binary).
    #[test]
    fn the_guide_lists_every_error_kind_with_its_exit_code() {
        let mut kinds: Vec<(String, u8)> = every_kind()
            .iter()
            .inspect(|e| has_a_sample(e))
            .map(|e| (e.kind().to_owned(), e.exit() as u8))
            .collect();
        kinds.sort();
        kinds.dedup();
        let guide = include_str!("../AGENTS.md");
        let section = guide
            .split("\n## Error kinds\n")
            .nth(1)
            .expect("AGENTS.md has an Error kinds section");
        let section = section.split("\n## ").next().unwrap_or(section);
        let mut listed: Vec<(String, u8)> = section
            .lines()
            .filter_map(|line| {
                let mut cells = line.split('|').map(str::trim).skip(1);
                let kind = cells.next()?.strip_prefix('`')?.strip_suffix('`')?;
                let exit = cells.next()?.parse().ok()?;
                Some((kind.to_owned(), exit))
            })
            .collect();
        listed.sort();
        assert_eq!(listed, kinds);
    }
}
