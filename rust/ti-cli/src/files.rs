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

//! Plain files the way every state and cache file of the tool is written: private to the
//! user and never half-written.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Replaces `path` with `bytes` in one step: a reader sees the old file or the new one,
/// and a crash leaves one of them, never a mixture. The temporary file sits in the same
/// directory so the rename stays on one file system.
///
/// # Errors
///
/// Any I/O error. Before the rename the temporary file is removed and `path` is
/// untouched; an error from the final directory sync means the new file is in place but
/// not yet known to survive a power loss.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_with(path, bytes, |from, to| fs::rename(from, to))
}

fn write_atomic_with(
    path: &Path,
    bytes: &[u8],
    rename: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let temp = path.with_file_name(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_synced(&temp, bytes).and_then(|()| rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return result;
    }
    #[cfg(unix)]
    sync_parent(path)?;
    Ok(())
}

/// Makes the rename itself durable: without it a power loss can bring the old file
/// back, and with the TSL state that rewinds the rollback check. Failing here is an
/// error although the new file is already in place, since durability is what the caller
/// asked for and cannot tell otherwise. Unix only: std cannot open a directory elsewhere.
#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::File::open(dir)?.sync_all()
}

fn write_synced(temp: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(temp)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Creates `path` and its missing parents, private to the user where the platform has
/// modes.
///
/// # Errors
///
/// Any I/O error.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// `text` as one path component: itself if it is plain, else the hex SHA-256 of it. An
/// unsafe value never names a path it could escape through, and two different unsafe
/// values never share one.
#[must_use]
pub fn path_component(text: &str) -> String {
    if is_plain_name(text) {
        return text.to_owned();
    }
    Sha256::digest(text.as_bytes())
        .iter()
        .fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
}

/// The one rule that keeps untrusted text inside its directory: 1 to 64 characters of
/// `A-Z a-z 0-9 . _ -`, not starting with a dot.
pub(crate) fn is_plain_name(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && !text.starts_with('.')
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ti-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn a_written_file_is_private_and_whole() {
        let dir = scratch("whole");
        let file = dir.join("a.json");
        write_atomic(&file, b"one").unwrap();
        write_atomic(&file, b"two").unwrap();
        assert_eq!(fs::read(&file).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_write_leaves_the_old_content() {
        let dir = scratch("failed");
        let file = dir.join("a.json");
        write_atomic(&file, b"old").unwrap();
        let failed = write_atomic_with(&file, b"new", |_, _| {
            Err(io::Error::other("rename refused"))
        });
        assert!(failed.is_err());
        assert_eq!(fs::read(&file).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_created_directory_is_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch("dirs");
        let deep = dir.join("a").join("b");
        create_private_dir(&deep).unwrap();
        for d in [dir.join("a"), deep] {
            assert_eq!(fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_safe_component_is_kept() {
        assert_eq!(path_component("abc-1.2_x"), "abc-1.2_x");
        assert_eq!(path_component(&"a".repeat(64)), "a".repeat(64));
    }

    #[test]
    fn an_unsafe_component_cannot_leave_its_directory() {
        for text in [
            "..",
            ".",
            "a/b",
            "../x",
            "",
            &"a".repeat(65),
            ".hidden",
            "a\\b",
        ] {
            let c = path_component(text);
            assert_eq!(c.len(), 64, "{text:?}");
            assert!(c.bytes().all(|b| b.is_ascii_hexdigit()), "{text:?}");
        }
    }

    #[test]
    fn distinct_unsafe_components_do_not_collide() {
        assert_ne!(path_component("a/b"), path_component("a_b"));
        assert_ne!(path_component("a/b"), path_component("a\\b"));
    }
}
