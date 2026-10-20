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

//! The files backend of spec/store (section I): one file per record, for small stores
//! and for inspecting records by hand. It has atomic take and works across processes,
//! but has neither atomic batch nor indexed queries.
//!
//! The tree is confined to its root: no operation follows a symbolic link below it. Each
//! directory on a record's path is checked to be a directory, not a link; new files are
//! created exclusively, which fails on an existing link; and a renamed or claimed file is
//! checked before it is read. Renames and removals act on links, never through them.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ti_store::store::files::{FilesMeta, encode_record, parse_record, record_path};
use ti_store::store::levels::{MAX_LEVEL, check_open};
use ti_store::store::{
    Backend, BatchOp, Capabilities, Name, Namespace, OsRandom, Page, Query, Random as _,
    StoreError, StoredRecord,
};
use ti_types::Timestamp;

/// How old a leftover temporary or claimed file must be before cleanup removes it
/// (STORE-083): older than any write or take in progress.
const STALE_AFTER: Duration = Duration::from_secs(3600);

/// Records below a root directory.
#[derive(Debug)]
pub struct FilesBackend {
    root: PathBuf,
}

impl FilesBackend {
    /// Opens or creates the tree at `root` and checks its format level (STORE-086,
    /// STORE-100).
    ///
    /// # Errors
    ///
    /// `malformed` or `unsupported_version` for the tree's `meta`, `backend_error` for
    /// I/O.
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        create_dirs(root)?;
        let backend = FilesBackend {
            root: root.to_path_buf(),
        };
        match read_file(&root.join("meta")) {
            Ok(raw) => {
                let meta = FilesMeta::parse(&raw)?;
                check_open(MAX_LEVEL, meta.level, meta.min_compatible)?;
            }
            Err(StoreError::NotFound) => {
                let meta = FilesMeta {
                    level: MAX_LEVEL,
                    min_compatible: MAX_LEVEL,
                };
                write_atomic(root, "meta", &meta.encode())?;
            }
            Err(e) => return Err(e),
        }
        Ok(backend)
    }

    /// The tree's levels (STORE-086, STORE-123); a files tree has no integrity check.
    ///
    /// # Errors
    ///
    /// `malformed` for its `meta`, `backend_error` for I/O.
    pub fn inspect(&self) -> Result<super::Inspection, StoreError> {
        let meta = FilesMeta::parse(&read_file(&self.root.join("meta"))?)?;
        Ok(super::Inspection {
            level: meta.level,
            min_compatible: meta.min_compatible,
            integrity: None,
        })
    }

    /// The directory and file name of a record. With `create`, missing directories are
    /// made; without, a missing one means there is no record.
    fn locate(
        &self,
        ns: &Namespace,
        name: &Name,
        create: bool,
    ) -> Result<Option<(PathBuf, String)>, StoreError> {
        let rel = record_path(ns, name);
        let (dirs, file) = rel.rsplit_once('/').expect("record paths have directories");
        let mut dir = self.root.join("v1");
        for part in std::iter::once("").chain(dirs.split('/')) {
            if !part.is_empty() {
                dir.push(part);
            }
            match fs::symlink_metadata(&dir) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return Err(not_a_directory(&dir)),
                Err(e) if e.kind() == ErrorKind::NotFound && create => make_dir(&dir)?,
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(io("open", &dir, &e)),
            }
        }
        Ok(Some((dir, file.to_owned())))
    }

    /// Visits every record file of `ns`, or of every namespace, with its name.
    fn walk(
        &self,
        ns: Option<&Namespace>,
        visit: &mut dyn FnMut(&Path, Name) -> Result<bool, StoreError>,
    ) -> Result<(), StoreError> {
        let top = self.root.join("v1");
        let namespaces = match ns {
            Some(ns) => vec![top.join(ns.as_str())],
            None => subdirs(&top)?,
        };
        for ns_dir in namespaces {
            for d1 in subdirs(&ns_dir)? {
                for d2 in subdirs(&d1)? {
                    for (path, file_name) in files(&d2)? {
                        let Some(name) = file_name
                            .strip_suffix(".rec")
                            .and_then(unhex)
                            .and_then(|b| Name::try_from(&b[..]).ok())
                        else {
                            continue;
                        };
                        if !visit(&path, name)? {
                            return Ok(());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn remove_leftovers(&self) {
        let Some(cutoff) = SystemTime::now().checked_sub(STALE_AFTER) else {
            return;
        };
        let top = self.root.join("v1");
        for ns_dir in subdirs(&top).unwrap_or_default() {
            for d1 in subdirs(&ns_dir).unwrap_or_default() {
                for d2 in subdirs(&d1).unwrap_or_default() {
                    for (path, file_name) in files(&d2).unwrap_or_default() {
                        if !file_name.contains(".tmp.") && !file_name.contains(".take.") {
                            continue;
                        }
                        let stale = fs::symlink_metadata(&path)
                            .and_then(|m| m.modified())
                            .is_ok_and(|t| t < cutoff);
                        if stale {
                            let _ = fs::remove_file(&path);
                        }
                    }
                }
            }
        }
    }
}

impl Backend for FilesBackend {
    fn capabilities(&self) -> Capabilities {
        // STORE-084
        Capabilities {
            atomic_take: true,
            atomic_batch: false,
            indexed: false,
            multi_process: true,
        }
    }

    async fn get(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let Some((dir, file)) = self.locate(ns, name, false)? else {
            return Err(StoreError::NotFound);
        };
        let record = parse_record(&read_file(&dir.join(file))?)?;
        if record.is_live(now) {
            Ok(record)
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn put(
        &self,
        ns: &Namespace,
        name: &Name,
        record: StoredRecord,
    ) -> Result<(), StoreError> {
        record.check()?;
        let (dir, file) = self.locate(ns, name, true)?.expect("created on the way");
        write_atomic(&dir, &file, &encode_record(&record))
    }

    /// STORE-082: the process whose rename succeeds owns the record.
    async fn take(
        &self,
        ns: &Namespace,
        name: &Name,
        now: Timestamp,
    ) -> Result<StoredRecord, StoreError> {
        let Some((dir, file)) = self.locate(ns, name, false)? else {
            return Err(StoreError::NotFound);
        };
        let stem = file.strip_suffix(".rec").unwrap_or(&file);
        let claim = dir.join(format!("{stem}.take.{}", suffix()?));
        match fs::rename(dir.join(&file), &claim) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(io("take", &dir.join(&file), &e)),
        }
        let read = read_file(&claim);
        let _ = fs::remove_file(&claim);
        let record = parse_record(&read?)?;
        if record.is_live(now) {
            Ok(record)
        } else {
            Err(StoreError::NotFound)
        }
    }

    async fn delete(&self, ns: &Namespace, name: &Name) -> Result<(), StoreError> {
        let Some((dir, file)) = self.locate(ns, name, false)? else {
            return Ok(());
        };
        let path = dir.join(file);
        match fs::remove_file(&path) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(io("delete", &path, &e)),
            _ => Ok(()),
        }
    }

    async fn batch(&self, _ops: Vec<BatchOp>) -> Result<(), StoreError> {
        Err(StoreError::CapabilityMissing("atomic batch"))
    }

    /// STORE-083: reads every file of the namespace.
    async fn query(&self, q: &Query) -> Result<Page, StoreError> {
        q.check()?;
        let mut found = Vec::new();
        self.walk(Some(&q.ns), &mut |path, name| {
            if q.cursor.is_some_and(|c| name <= c) {
                return Ok(true);
            }
            let record = match read_file(path) {
                Ok(raw) => parse_record(&raw)?,
                Err(StoreError::NotFound) => return Ok(true),
                Err(e) => return Err(e),
            };
            if record.is_live(q.now) && record.matches(q) {
                found.push((name, record));
            }
            Ok(true)
        })?;
        found.sort_by_key(|(name, _)| *name);
        found.truncate(q.limit);
        Ok(Page::from_matches(found, q.limit))
    }

    /// STORE-017, STORE-083: also removes leftover temporary and claimed files older
    /// than an hour.
    async fn cleanup(&self, now: Timestamp, limit: usize) -> Result<usize, StoreError> {
        if limit == 0 {
            return Err(StoreError::InvalidArgument("limit"));
        }
        let mut removed = 0;
        self.walk(None, &mut |path, _| {
            if removed == limit {
                return Ok(false);
            }
            let expired = read_file(path)
                .and_then(|raw| parse_record(&raw))
                .is_ok_and(|r| !r.is_live(now));
            if expired && fs::remove_file(path).is_ok() {
                removed += 1;
            }
            Ok(true)
        })?;
        self.remove_leftovers();
        Ok(removed)
    }
}

/// STORE-081: a new temporary file in `dir`, flushed, renamed into place, and the
/// directory flushed after the rename.
fn write_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<(), StoreError> {
    let tmp = dir.join(format!("{name}.tmp.{}", suffix()?));
    let written = (|| {
        let mut options = OpenOptions::new();
        // create_new also refuses a link planted at the temporary name
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut f = options.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, dir.join(name))
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(io("write", &dir.join(name), &e));
    }
    sync_dir(dir)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io("sync", dir, &e))
}

/// Windows cannot open a directory as a file; the rename is as durable as it allows.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Reads a regular file, never through a link; a missing file is `not_found`.
fn read_file(path: &Path) -> Result<Vec<u8>, StoreError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => {}
        Ok(_) => return Err(not_a_file(path)),
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(StoreError::NotFound),
        Err(e) => return Err(io("read", path, &e)),
    }
    fs::read(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => StoreError::NotFound,
        _ => io("read", path, &e),
    })
}

/// STORE-085: directories with mode 0700.
fn make_dir(dir: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(dir) {
        Ok(()) => {}
        // another process made it in between
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io("create", dir, &e)),
    }
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(not_a_directory(dir)),
        Err(e) => Err(io("create", dir, &e)),
    }
}

/// The root and its parents, as the user configured them.
fn create_dirs(root: &Path) -> Result<(), StoreError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(root).map_err(|e| io("create", root, &e))
}

/// The subdirectories of `dir`, never a link; none if `dir` does not exist.
fn subdirs(dir: &Path) -> Result<Vec<PathBuf>, StoreError> {
    Ok(entries(dir)?
        .into_iter()
        .filter(|(_, t, _)| t.is_dir())
        .map(|(p, _, _)| p)
        .collect())
}

/// The regular files of `dir` with their names.
fn files(dir: &Path) -> Result<Vec<(PathBuf, String)>, StoreError> {
    Ok(entries(dir)?
        .into_iter()
        .filter(|(_, t, _)| t.is_file())
        .map(|(p, _, n)| (p, n))
        .collect())
}

fn entries(dir: &Path) -> Result<Vec<(PathBuf, fs::FileType, String)>, StoreError> {
    let read = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io("list", dir, &e)),
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = entry.map_err(|e| io("list", dir, &e))?;
        // file_type does not follow links, so a link is neither a directory nor a file
        let file_type = entry.file_type().map_err(|e| io("list", dir, &e))?;
        if let Ok(name) = entry.file_name().into_string() {
            out.push((entry.path(), file_type, name));
        }
    }
    Ok(out)
}

fn suffix() -> Result<String, StoreError> {
    let mut r = [0u8; 8];
    OsRandom.fill(&mut r)?;
    Ok(hex(&r))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn io(what: &str, path: &Path, e: &std::io::Error) -> StoreError {
    StoreError::Backend(format!("{what} {}: {e}", path.display()))
}

fn not_a_directory(path: &Path) -> StoreError {
    StoreError::Backend(format!(
        "{} is not a directory (a symbolic link?)",
        path.display()
    ))
}

fn not_a_file(path: &Path) -> StoreError {
    StoreError::Backend(format!(
        "{} is not a regular file (a symbolic link?)",
        path.display()
    ))
}
