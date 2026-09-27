//! Konnektor access for the `connector` commands: which `.kon` file (resolved as the Go
//! `ti` resolves it, sharing its files), the transport, the service directory through
//! the cache, and one diagnostic line per call.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ti_connector_client::ureq::UreqTransport;
use ti_connector_client::{
    Connector, Dotkon, Request, Response, Timeouts, Transport, TransportError,
};
use ti_pki::load::{Cache, CachePolicy, SystemClock};

use crate::block::block_on;
use crate::cli::{ConnectorArgs, GlobalArgs};
use crate::error::CliError;
use crate::output::{Output, diagnostic};
use crate::paths;

/// A Konnektor ready for calls.
pub struct Session {
    /// The Konnektor.
    pub connector: Connector<Logged<UreqTransport>>,
    /// Its configuration.
    pub dotkon: Dotkon,
    /// The configuration's name, e.g. `default`.
    pub name: String,
}

/// `$XDG_CONFIG_HOME/telematik/connectors`, or `~/.config/…` on every platform, as the
/// Go `ti` has it.
pub fn connectors_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::home_dir().map(|home| home.join(".config")))?;
    Some(base.join("telematik").join("connectors"))
}

/// The file `connector use` writes the selected name to.
pub fn active_file() -> Option<PathBuf> {
    connectors_dir().map(|dir| dir.join("active"))
}

/// The configuration to use: `-c`/`TI_CONNECTOR_CONFIG`, else the active selection,
/// else `default`; with where the choice came from.
pub fn selected(explicit: Option<&str>) -> (String, &'static str) {
    if let Some(name) = explicit.filter(|n| !n.is_empty()) {
        return (name.to_owned(), "-c or TI_CONNECTOR_CONFIG");
    }
    let active = active_file()
        .and_then(|file| std::fs::read_to_string(file).ok())
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    match active {
        Some(name) => (name, "the active selection"),
        None => ("default".to_owned(), "the default name"),
    }
}

/// The file of configuration `name`: a path as given (with or without `.kon`), else
/// `NAME`, `NAME.kon` in the current directory, then in [`connectors_dir`].
///
/// # Errors
///
/// [`CliError::ConnectorConfig`] naming where it looked.
pub fn resolve(name: &str) -> Result<PathBuf, CliError> {
    let name = match name.strip_prefix("~/") {
        Some(rest) => std::env::home_dir().map_or_else(|| PathBuf::from(name), |h| h.join(rest)),
        None => PathBuf::from(name),
    };
    let with_ext = |p: &Path| {
        let mut p = p.as_os_str().to_owned();
        p.push(".kon");
        PathBuf::from(p)
    };
    let mut candidates = vec![name.clone(), with_ext(&name)];
    let is_path = name.is_absolute() || name.components().count() > 1;
    if !is_path && let Some(dir) = connectors_dir() {
        candidates.push(with_ext(&dir.join(&name)));
        candidates.push(dir.join(&name));
    }
    candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
        let searched = connectors_dir()
            .filter(|_| !is_path)
            .map(|dir| format!(" (searched the current directory and {})", dir.display()))
            .unwrap_or_default();
        CliError::ConnectorConfig(format!(
            "connector configuration {:?} not found{searched}",
            name.display().to_string()
        ))
    })
}

/// Reads and validates the `.kon` file at `path`.
///
/// # Errors
///
/// [`CliError::ConnectorConfig`].
pub fn read(path: &Path) -> Result<Dotkon, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::ConnectorConfig(format!("{}: {e}", path.display())))?;
    Dotkon::parse(&bytes).map_err(|e| CliError::ConnectorConfig(format!("{}: {e}", path.display())))
}

/// Opens the selected Konnektor: reads its `.kon` file, sets up TLS from it, and loads
/// the service directory (through the cache unless `--no-cache`).
///
/// # Errors
///
/// [`CliError::ConnectorConfig`] or [`CliError::Connector`].
pub fn open(args: &ConnectorArgs, global: &GlobalArgs, out: &Output) -> Result<Session, CliError> {
    let (name, source) = selected(args.connector_config.as_deref());
    let path = resolve(&name).map_err(|e| match (source, e) {
        ("the active selection", CliError::ConnectorConfig(message)) => {
            CliError::ConnectorConfig(format!(
                "{message}; it is the active selection, change it with `{} connector use`",
                crate::BIN
            ))
        }
        (_, e) => e,
    })?;
    out.verbose(
        1,
        format_args!("connector {name} ({source}): {}", path.display()),
    );
    let dotkon = read(&path)?;
    if !dotkon.variables.is_empty() {
        out.verbose(
            1,
            format_args!(
                "expanded from the environment: {}",
                dotkon.variables.join(", ")
            ),
        );
    }
    let timeouts = Timeouts {
        short: args.connector_timeout,
        long: args.card_timeout,
    };
    out.verbose(
        1,
        format_args!(
            "timeouts: {} s per call, {} s with the card terminal",
            timeouts.short.as_secs(),
            timeouts.long.as_secs()
        ),
    );
    let mut config = ureq::Agent::config_builder()
        .timeout_connect(Some(global.net.connect_timeout))
        .user_agent(global.net.user_agent());
    // Only an explicit -x: a Konnektor is in the local network, and a proxy from the
    // environment would route its traffic (and credentials) elsewhere.
    if let Some(proxy) = global.net.proxy.as_deref().filter(|p| !p.is_empty()) {
        let proxy =
            ureq::Proxy::new(proxy).map_err(|e| CliError::HttpSetup(format!("proxy: {e}")))?;
        config = config.proxy(Some(proxy));
    }
    let transport = Logged {
        inner: UreqTransport::new(&dotkon, config).map_err(CliError::Connector)?,
        verbosity: out.verbosity(),
    };
    let connector = if args.no_cache {
        block_on(Connector::connect(&dotkon, transport, timeouts)).map_err(CliError::Connector)?
    } else {
        let store =
            crate::cache::FileCacheStore::new(paths::cache_dir(global.cache_dir.as_deref())?);
        let cache = Cache::new(store, SystemClock, CachePolicy::default());
        let (connector, meta) = block_on(Connector::connect_cached(
            &dotkon, transport, timeouts, &cache,
        ))
        .map_err(CliError::Connector)?;
        out.verbose(1, format_args!("service directory from {:?}", meta.source));
        connector
    };
    Ok(Session {
        connector,
        dotkon,
        name,
    })
}

/// The transport with a diagnostic per call: `-v` a line, `-vv` also the bodies, with
/// long base64 runs (documents, certificates) shortened. Never the `Authorization`
/// header, which only the inner transport sees.
pub struct Logged<T> {
    inner: T,
    verbosity: u8,
}

impl<T: Transport> Transport for Logged<T> {
    async fn send(&self, request: &Request<'_>) -> Result<Response, TransportError> {
        let what = request.operation.map_or_else(
            || format!("GET {}", request.url),
            |op| {
                format!(
                    "{} {} {} → {}",
                    op.service, op.version, op.name, request.url
                )
            },
        );
        if self.verbosity >= 2 && !request.body.is_empty() {
            diagnostic(format_args!(
                "request {what}\n{}",
                shorten(&mask_user_id(request.body))
            ));
        }
        let start = Instant::now();
        let result = self.inner.send(request).await;
        let took = start.elapsed();
        if self.verbosity >= 1 {
            match &result {
                Ok(response) => diagnostic(format_args!(
                    "{what}: {} in {}",
                    response.status,
                    millis(took)
                )),
                Err(e) => diagnostic(format_args!("{what}: {e} after {}", millis(took))),
            }
        }
        if self.verbosity >= 2
            && let Ok(response) = &result
        {
            diagnostic(format_args!("response\n{}", shorten(&response.body)));
        }
        result
    }
}

fn millis(d: Duration) -> String {
    format!("{} ms", d.as_millis())
}

/// The body with the content of `UserId` elements masked: in a comfort signature
/// session it lets anyone with the same context sign without a PIN.
fn mask_user_id(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("UserId>") {
        let open = start + "UserId>".len();
        // `<…UserId>` opens the element and `</…UserId>` closes it; only an opening
        // tag is followed by the value.
        let closing = rest[..start]
            .rfind('<')
            .is_some_and(|lt| rest[lt + 1..].starts_with('/'));
        out.push_str(&rest[..open]);
        rest = &rest[open..];
        if !closing {
            let end = rest.find('<').unwrap_or(rest.len());
            if end > 0 {
                out.push_str("***");
            }
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out.into_bytes()
}

/// The body as text, each base64-looking run over 120 characters replaced by its
/// start and length: SOAP stays readable while documents do not flood the terminal.
fn shorten(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let mut out = String::with_capacity(text.len().min(8192));
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() > 120 {
            out.push_str(&run[..40]);
            write!(out, "…[{} characters]", run.len()).expect("writing to a String cannot fail");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_ids_are_masked() {
        let body =
            b"<c:Context><c:UserId>2b0a-secret</c:UserId><c:MandantId>M</c:MandantId></c:Context>";
        assert_eq!(
            String::from_utf8(mask_user_id(body)).unwrap(),
            "<c:Context><c:UserId>***</c:UserId><c:MandantId>M</c:MandantId></c:Context>"
        );
    }

    #[test]
    fn long_base64_runs_are_shortened() {
        let body = format!("<Data>{}</Data><Name>C.AUT</Name>", "QUJD".repeat(100));
        let short = shorten(body.as_bytes());
        assert!(short.starts_with("<Data>QUJDQUJD"), "{short}");
        assert!(
            short.contains("…[400 characters]</Data><Name>C.AUT</Name>"),
            "{short}"
        );
    }

    #[test]
    fn paths_are_used_as_given() {
        let dir = std::env::temp_dir().join(format!("ti-kon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("praxis.kon");
        std::fs::write(&file, "{}").unwrap();
        assert_eq!(resolve(file.to_str().unwrap()).unwrap(), file);
        assert_eq!(resolve(dir.join("praxis").to_str().unwrap()).unwrap(), file);
        assert!(matches!(
            resolve(dir.join("missing").to_str().unwrap()),
            Err(CliError::ConnectorConfig(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
