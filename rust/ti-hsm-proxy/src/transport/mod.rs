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

//! The transports of the HSM proxy interface and what they share: where the sidecar listens
//! (servers.md rule 29), binding a Unix socket or a TCP address, and the sidecar's own TLS
//! ([`tls`]). A transport decodes, calls [`crate::HsmProxy`] and encodes; it decides nothing.
//!
//! - [`grpc`], behind the feature `grpc`: `hsm-proxy.proto` (gemSpec_ZETA A_28829) and
//!   `grpc.health.v1`.

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::net::{TcpListener, UnixListener};

#[cfg(feature = "grpc")]
pub mod grpc;
pub mod tls;

use tls::TlsListener;

/// Where the sidecar listens (servers.md rule 29).
pub enum Listener {
    /// A Unix socket inside the pod: no TLS, and no check of who calls; the keys served are
    /// the ones configured.
    Unix(PathBuf),
    /// A TCP address inside the cluster with the sidecar's own TLS, mTLS when the listener
    /// has clients. `probe` is the Unix socket that serves `grpc.health.v1` alone, for
    /// `hsm-proxy health`, since a kubelet's gRPC probe speaks no TLS.
    Tls {
        /// The address to listen on.
        address: SocketAddr,
        /// The listener's TLS.
        tls: TlsListener,
        /// The health socket.
        probe: PathBuf,
    },
    /// A TCP address inside the cluster in plaintext (h2c), which the operator has accepted:
    /// the deployment protects the connection and decides who calls. `probe` as for
    /// [`Listener::Tls`].
    Plaintext {
        /// The address to listen on.
        address: SocketAddr,
        /// The health socket.
        probe: PathBuf,
    },
}

/// A listener once bound, for a transport to serve on.
pub(crate) enum Bound {
    /// The Unix socket.
    Unix(UnixListener),
    /// The TCP listener, its TLS and the health socket beside it.
    Tls(TcpListener, TlsListener, UnixListener),
    /// The TCP listener in plaintext and the health socket beside it.
    Plaintext(TcpListener, UnixListener),
}

impl Listener {
    /// Binds the listener, and beside a TCP one its health socket.
    pub(crate) async fn bind(self) -> io::Result<Bound> {
        Ok(match self {
            Listener::Unix(socket) => Bound::Unix(bind_unix(&socket).await?),
            Listener::Tls {
                address,
                tls,
                probe,
            } => Bound::Tls(bind_tcp(address).await?, tls, bind_unix(&probe).await?),
            Listener::Plaintext { address, probe } => {
                Bound::Plaintext(bind_tcp(address).await?, bind_unix(&probe).await?)
            }
        })
    }
}

async fn bind_unix(socket: &Path) -> io::Result<UnixListener> {
    remove_stale_socket(socket).await?;
    open_socket(socket)
}

async fn bind_tcp(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("{address}: {e}")))
}

/// Removes a socket file an earlier run left at `socket`, but only when nothing answers on
/// it (rule 29): a second sidecar on the same path is refused, not displaced. Any other file
/// at the path is left alone.
async fn remove_stale_socket(socket: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt as _;
    match std::fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() => {
            match tokio::net::UnixStream::connect(socket).await {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{}: another process answers on it", socket.display()),
                )),
                // Refused means bound by nobody: the file of a process that ended. Any other
                // failure, as no permission to connect, says nothing of that.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(socket)
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(io::Error::new(
                    e.kind(),
                    format!("{}: not known to be stale: {e}", socket.display()),
                )),
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", socket.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Owner and group read and write, nothing for others: what lets the workload's container,
/// under another arbitrary UID with group 0 or the pod's `fsGroup`, connect (rules 27 and
/// 29). The socket gets the group of a directory with the setgid bit, as an `emptyDir` with
/// `fsGroup` has, or else the process's primary group, which is 0 on OpenShift.
const SOCKET_MODE: u32 = 0o660;

/// Counts the binds of this process, so that each gets a staging directory of its own: two
/// sockets bound at once must not share one.
static BINDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Binds the socket where nobody else can reach it, a directory of mode 0700 beside its
/// path, gives it [`SOCKET_MODE`] and only then links it to its path. However the umask is
/// set, the socket is never reachable with other permissions; and a link, unlike a rename,
/// does not replace a socket another process bound at the path meanwhile.
fn open_socket(socket: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let named = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", socket.display()));
    let parent = socket
        .parent()
        .ok_or_else(|| named(io::Error::from(io::ErrorKind::InvalidInput)))?;
    let bind = BINDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let staging = parent.join(format!(".hsm-proxy-{}-{bind}", std::process::id()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(named)?;
    let inner = staging.join("s");
    let bound = UnixListener::bind(&inner).and_then(|listener| {
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(SOCKET_MODE))?;
        std::fs::hard_link(&inner, socket)?;
        Ok(listener)
    });
    let _ = std::fs::remove_file(&inner);
    let _ = std::fs::remove_dir(&staging);
    bound.map_err(named)
}
