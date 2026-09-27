//! `ti cache clear`: deletes the downloaded trust material and Konnektor service
//! directories. Only the subtrees this tool writes are removed, never the cache
//! directory itself: `--cache-dir` may point anywhere, and other TI tools share the
//! folder.

use std::io;
use std::path::Path;

use serde::Serialize;

use crate::cli::GlobalArgs;
use crate::error::{CliError, Exit};
use crate::output::{Document, Line, Output, SCHEMA};
use crate::paths;

/// The subtrees the cache store writes (see [`crate::cache`]): ti-pki's trust material
/// and ti-connector-client's service directories.
const SUBTREES: [&str; 2] = ["ti-pki", "ti-connector"];

/// The JSON document.
#[derive(Serialize)]
struct Report {
    schema: u32,
    /// The cache directory whose subtrees were cleared.
    path: String,
    removed_files: u64,
    removed_bytes: u64,
}

/// Runs `ti cache clear`.
pub fn clear(global: &GlobalArgs, out: &Output) -> Result<Exit, CliError> {
    let base = paths::cache_dir(global.cache_dir.as_deref())?;
    let (mut files, mut bytes) = (0, 0);
    for dir in SUBTREES.map(|subtree| base.join(subtree)) {
        let (f, b) = size(&dir).map_err(|e| cache_error(&dir, &e))?;
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(cache_error(&dir, &e)),
        }
        files += f;
        bytes += b;
    }
    let report = Report {
        schema: SCHEMA,
        path: base.display().to_string(),
        removed_files: files,
        removed_bytes: bytes,
    };
    if out.is_json() {
        out.json(&report)?;
    } else {
        let mut doc = Document::default();
        doc.section("Cache");
        doc.field("path", Line::code(&report.path));
        doc.field(
            "removed",
            if files == 0 {
                Line::dim("nothing was cached")
            } else {
                Line::text(format!("{files} files, {} KiB", bytes.div_ceil(1024)))
            },
        );
        out.render(&doc)?;
    }
    Ok(Exit::Ok)
}

/// Files and bytes below `dir`; symbolic links are counted, not followed.
fn size(dir: &Path) -> io::Result<(u64, u64)> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    let (mut files, mut bytes) = (0, 0);
    for entry in entries {
        let entry = entry?;
        let meta = entry.path().symlink_metadata()?;
        if meta.is_dir() {
            let (f, b) = size(&entry.path())?;
            files += f;
            bytes += b;
        } else {
            files += 1;
            bytes += meta.len();
        }
    }
    Ok((files, bytes))
}

fn cache_error(dir: &Path, error: &io::Error) -> CliError {
    CliError::Output(io::Error::new(
        error.kind(),
        format!("{}: {error}", dir.display()),
    ))
}
