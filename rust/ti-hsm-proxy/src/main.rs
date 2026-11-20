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

//! `hsm-proxy`, the key provider sidecar: gematik's HSM proxy interface on a Unix socket,
//! every key reached over PKCS#11. Configured by its environment (`config.rs`); without
//! the `grpc` feature it has no transport and refuses to start.

mod config;

use std::process::ExitCode;

use config::Config;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => serve(),
        ["health", "ready"] => health(Probe::Ready),
        ["health", "live"] => health(Probe::Live),
        _ => {
            eprintln!(
                "usage: hsm-proxy                serve, configured by HSM_PROXY_* variables\n\
                 \x20      hsm-proxy health ready   exit 0 if the sidecar is SERVING (startup, readiness)\n\
                 \x20      hsm-proxy health live    exit 0 if the sidecar answers at all (liveness)"
            );
            ExitCode::from(2)
        }
    }
}

fn serve() -> ExitCode {
    let config = match Config::from_vars(
        |name| std::env::var(name).ok(),
        |path| std::fs::read_to_string(path),
    ) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("hsm-proxy: {e}");
            return ExitCode::FAILURE;
        }
    };
    match run(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hsm-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// What an exec probe asks the sidecar's own socket, since a kubelet's gRPC and HTTP
/// probes do not reach a Unix socket.
#[derive(Clone, Copy)]
enum Probe {
    /// `grpc.health.v1` reports SERVING: the token answers. Startup and readiness.
    Ready,
    /// The socket answers, SERVING or not. Liveness: a restart does not bring back an HSM,
    /// so the token's state does not restart the sidecar.
    Live,
}

#[cfg(feature = "grpc")]
fn health(probe: Probe) -> ExitCode {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    let socket = match config::listen(|name| std::env::var(name).ok()) {
        Ok(listen) => listen.probe_socket(),
        Err(e) => {
            eprintln!("hsm-proxy health: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("hsm-proxy health: {e}");
            return ExitCode::FAILURE;
        }
    };
    let answer = runtime.block_on(async {
        tokio::time::timeout(TIMEOUT, ti_hsm_proxy::transport::grpc::probe(&socket)).await
    });
    match (answer, probe) {
        (Ok(Ok(true)), _) | (Ok(Ok(false)), Probe::Live) => ExitCode::SUCCESS,
        (Ok(Ok(false)), Probe::Ready) => {
            eprintln!("hsm-proxy health: NOT_SERVING, the token does not answer");
            ExitCode::FAILURE
        }
        (Ok(Err(e)), _) => {
            eprintln!("hsm-proxy health: {}: {e}", socket.display());
            ExitCode::FAILURE
        }
        (Err(_), _) => {
            eprintln!("hsm-proxy health: no answer within {TIMEOUT:?}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "grpc"))]
fn health(_: Probe) -> ExitCode {
    eprintln!("hsm-proxy health: built without a transport");
    ExitCode::FAILURE
}

#[cfg(not(feature = "grpc"))]
fn run(_: &Config) -> Result<(), String> {
    Err("built without a transport; the grpc feature serves the interface".to_owned())
}

#[cfg(feature = "grpc")]
fn run(config: &Config) -> Result<(), String> {
    use std::sync::Arc;

    use cryptoki::types::AuthPin;
    use sha2::Digest as _;
    use ti_hsm_proxy::{HsmProxy, MissingKeys, Module};

    // Rule 7: what is loaded is what was measured. The file is hashed, then loaded by path
    // from a read-only mount, so the two cannot differ.
    if let Some(expected) = config.module_sha256 {
        let module = std::fs::read(&config.module)
            .map_err(|e| format!("{}: {e}", config.module.display()))?;
        if sha2::Sha256::digest(&module).as_slice() != expected {
            return Err(format!(
                "{}: SHA-256 is not HSM_PROXY_PKCS11_MODULE_SHA256",
                config.module.display()
            ));
        }
    }
    // Rule 7: the module loaded at run time is reported with the configuration.
    let pinned = config.module_sha256.map_or_else(
        || "not pinned (simulator)".to_owned(),
        |sha| {
            sha.iter().fold(String::from("SHA-256 "), |mut hex, byte| {
                use std::fmt::Write as _;
                let _ = write!(hex, "{byte:02x}");
                hex
            })
        },
    );
    let user_pin = match &config.user_pin {
        Some(path) => {
            let pin = std::fs::read_to_string(path)
                .map_err(|e| format!("HSM_PROXY_USER_PIN_PATH {}: {e}", path.display()))?;
            AuthPin::from(pin.trim_end_matches(['\n', '\r']))
        }
        #[cfg(feature = "simulator")]
        None => AuthPin::from(simulator::USER_PIN),
        #[cfg(not(feature = "simulator"))]
        None => return Err("HSM_PROXY_USER_PIN_PATH is not set".to_owned()),
    };
    let module = Module::load(&config.module).map_err(|e| e.to_string())?;
    #[cfg(feature = "simulator")]
    let missing = if config.simulator {
        simulator::provision(&module, &config.token, &user_pin)?;
        if let Some(path) = &config.simulator_seed {
            MissingKeys::Derive(simulator::seed(path)?)
        } else {
            eprintln!("hsm-proxy: simulator mode: missing keys are made at random");
            MissingKeys::Make
        }
    } else {
        MissingKeys::Refuse
    };
    #[cfg(not(feature = "simulator"))]
    let missing = MissingKeys::Refuse;
    let hsm_info = module.describe().map_err(|e| e.to_string())?;
    let pool = module
        .pool(&config.token, &user_pin, config.sessions)
        .map_err(|e| e.to_string())?;
    // The module stays loaded to the end of the process: unloading it at exit gains nothing,
    // and SoftHSM2 crashes in its exit handlers once it was unloaded after a logout. The
    // sessions close when the pool goes; nothing is finalised before the process ends.
    std::mem::forget(module);
    let proxy = HsmProxy::start(
        pool,
        &config.keys,
        missing,
        config.wait,
        config.iv,
        hsm_info.clone(),
    )
    .map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let (listener, mode) = listener(&config.listen)?;
    eprintln!(
        "hsm-proxy {}: {hsm_info} from {} ({pinned}), token {}, {} sessions, {} keys, {mode}",
        env!("CARGO_PKG_VERSION"),
        config.module.display(),
        config.token,
        config.sessions,
        config.keys.len(),
    );
    runtime
        .block_on(ti_hsm_proxy::transport::grpc::serve(
            Arc::new(proxy),
            listener,
            config.health_interval,
            shutdown(),
        ))
        .map_err(|e| e.to_string())
}

/// The listener of `listen`, with its TLS material read and checked (rules 17 and 29), and
/// the line that reports its mode.
#[cfg(feature = "grpc")]
fn listener(
    listen: &config::Listen,
) -> Result<(ti_hsm_proxy::transport::Listener, String), String> {
    use ti_hsm_proxy::transport::Listener;
    use ti_hsm_proxy::transport::tls::{Clients, TlsListener};

    let read = |path: &std::path::Path| {
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
    };
    Ok(match listen {
        config::Listen::Unix(socket) => (
            Listener::Unix(socket.clone()),
            format!("on unix://{}", socket.display()),
        ),
        config::Listen::Tls {
            address,
            cert,
            key,
            clients,
        } => {
            let ca = clients.as_ref().map(|(ca, _)| read(ca)).transpose()?;
            let tls = TlsListener::new(
                &read(cert)?,
                &read(key)?,
                clients
                    .as_ref()
                    .zip(ca.as_deref())
                    .map(|((_, allow), ca)| Clients {
                        ca,
                        allow: allow.clone(),
                    }),
                std::time::SystemTime::now(),
            )
            .map_err(|e| format!("HSM_PROXY_LISTEN_TLS_*: {e}"))?;
            let mode = match clients {
                Some((_, allow)) => {
                    format!("on https://{address}, mTLS admitting {}", allow.join(", "))
                }
                None => format!("on https://{address}, TLS without client certificates"),
            };
            let probe = listen.probe_socket();
            (
                Listener::Tls {
                    address: *address,
                    tls,
                    probe: probe.clone(),
                },
                format!("{mode}, health on unix://{}", probe.display()),
            )
        }
        config::Listen::Plaintext { address } => {
            let probe = listen.probe_socket();
            (
                Listener::Plaintext {
                    address: *address,
                    probe: probe.clone(),
                },
                format!(
                    "on http://{address} in plaintext, accepted by the operator, the caller unchecked (servers.md rule 29), health on unix://{}",
                    probe.display()
                ),
            )
        }
    })
}

/// The simulator mode, in a build with the feature `simulator` only (servers.md rule 17).
#[cfg(all(feature = "grpc", feature = "simulator"))]
mod simulator {
    use cryptoki::types::AuthPin;
    use ti_hsm_proxy::Module;

    // TEST-ONLY: the simulator mode provisions a software token, whose keys protect nothing.
    const SO_PIN: &str = "so-pin-TEST-ONLY";
    pub const USER_PIN: &str = "user-pin-TEST-ONLY";

    /// The seed of derived keys: the SHA-256 of the file at `path`, of at least 16 bytes.
    pub fn seed(path: &std::path::Path) -> Result<[u8; 32], String> {
        use sha2::Digest as _;
        let bytes = std::fs::read(path)
            .map_err(|e| format!("HSM_PROXY_SIMULATOR_SEED_PATH {}: {e}", path.display()))?;
        if bytes.len() < 16 {
            return Err(format!(
                "HSM_PROXY_SIMULATOR_SEED_PATH {}: a seed of at least 16 bytes",
                path.display()
            ));
        }
        eprintln!(
            "hsm-proxy: simulator mode: missing keys are derived from the seed in {}",
            path.display()
        );
        Ok(sha2::Sha256::digest(&bytes).into())
    }

    /// Provisions the token `label` if it is not, with the TEST-ONLY PINs, and says so.
    pub fn provision(module: &Module, label: &str, user_pin: &AuthPin) -> Result<(), String> {
        eprintln!("hsm-proxy: simulator mode: token {label} is provisioned with TEST-ONLY PINs");
        module
            .provision(label, &AuthPin::from(SO_PIN), user_pin)
            .map_err(|e| e.to_string())
    }
}

#[cfg(feature = "grpc")]
async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut term), Ok(mut int)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
        // Without signal handlers the sidecar runs until it is killed.
        _ => std::future::pending().await,
    }
}
