//! Where TI tools keep their state: one `telematik` folder shared by all of them, in the
//! XDG layout on every Unix including macOS, and in the local application data on
//! Windows.

use std::path::{Path, PathBuf};

use crate::error::CliError;

/// The folder all TI tools share, and this tool's name within it.
const GROUP: &str = "telematik";
const TOOL: &str = "ti";

/// The cache directory: `explicit` (from `--cache-dir` or `TI_CACHE_DIR`) if given,
/// else the platform default.
pub fn cache_dir(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    default_cache_base().map(|base| base.join(GROUP).join(TOOL))
}

/// The state directory: kept across runs, unlike the cache (`cache clear` never
/// touches it); `$XDG_STATE_HOME/telematik/ti`, or `~/.local/state/telematik/ti`, or the
/// local application data on Windows.
pub fn state_dir() -> Result<PathBuf, CliError> {
    default_state_base().map(|base| base.join(GROUP).join(TOOL))
}

#[cfg(windows)]
fn default_state_base() -> Result<PathBuf, CliError> {
    default_cache_base().map(|base| base.join("state"))
}

#[cfg(not(windows))]
fn default_state_base() -> Result<PathBuf, CliError> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from)
        && xdg.is_absolute()
    {
        return Ok(xdg);
    }
    std::env::home_dir()
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".local").join("state"))
        .ok_or(CliError::CacheDir("no home directory"))
}

#[cfg(windows)]
fn default_cache_base() -> Result<PathBuf, CliError> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(CliError::CacheDir("LOCALAPPDATA is not set"))
}

/// `$XDG_CACHE_HOME`, or `~/.cache`. A relative XDG path is invalid by the XDG spec
/// and ignored.
#[cfg(not(windows))]
fn default_cache_base() -> Result<PathBuf, CliError> {
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from)
        && xdg.is_absolute()
    {
        return Ok(xdg);
    }
    std::env::home_dir()
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".cache"))
        .ok_or(CliError::CacheDir("no home directory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_directory_wins() {
        let dir = Path::new("/tmp/somewhere");
        assert_eq!(cache_dir(Some(dir)).unwrap(), dir);
    }

    #[test]
    fn default_ends_in_the_shared_group() {
        if let Ok(dir) = cache_dir(None) {
            assert!(
                dir.ends_with(Path::new("telematik").join("ti")),
                "{}",
                dir.display()
            );
        }
    }
}
