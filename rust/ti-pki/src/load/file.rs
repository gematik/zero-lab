//! [`FileTransport`]: artefacts from files, typically a mounted Kubernetes ConfigMap.
//!
//! Kubernetes notes:
//!
//! - A ConfigMap volume updates by atomically repointing a `..data` symlink. The
//!   transport therefore reads through the configured path on every call and never keeps
//!   a canonicalised path or an open handle.
//! - `subPath` mounts never receive updates; mount the whole volume.
//! - An update reaches the pod after up to the kubelet sync period plus its cache TTL
//!   (about a minute by default), then after the next reload tick.
//! - Put roots.json and the TSL in one ConfigMap so they update together.
//! - inotify is unreliable on these mounts (the files themselves never change, the
//!   symlink does); poll through the reloader instead of watching.

use std::collections::HashMap;
use std::path::PathBuf;

use super::artifact::{Artifact, ArtifactRequest, ArtifactResponse, ResponseMeta, content_etag};
use super::transport::{PostRequest, Transport, TransportError, TransportErrorKind};
use ti_cache::Source;

/// Reads each artefact from a configured path. The entity tag is the SHA-256 of the
/// contents, so rewriting a file with identical bytes answers "not modified".
#[derive(Clone, Debug, Default)]
pub struct FileTransport {
    paths: HashMap<Artifact, PathBuf>,
}

impl FileTransport {
    /// A transport reading roots.json and the TSL from these paths.
    pub fn new(roots: impl Into<PathBuf>, tsl: impl Into<PathBuf>) -> Self {
        FileTransport {
            paths: HashMap::from([(Artifact::Roots, roots.into()), (Artifact::Tsl, tsl.into())]),
        }
    }
}

impl Transport for FileTransport {
    async fn get(&self, req: &ArtifactRequest<'_>) -> Result<ArtifactResponse, TransportError> {
        let path = self
            .paths
            .get(&req.artifact)
            .ok_or_else(|| TransportError {
                kind: TransportErrorKind::Other,
                message: format!("no path configured for {}", req.artifact),
                retryable: false,
            })?;
        // Small files, read rarely: blocking I/O is acceptable here and keeps the
        // transport free of any executor.
        let body = std::fs::read(path).map_err(|e| TransportError {
            kind: TransportErrorKind::Io,
            message: format!("{}: {e}", path.display()),
            retryable: true,
        })?;
        let etag = content_etag(&body);
        let meta = ResponseMeta {
            etag: Some(etag.clone()),
            last_modified: None,
            max_age: None,
            source: Source::File,
        };
        if req.etag == Some(etag.as_str()) {
            return Ok(ArtifactResponse::NotModified { meta });
        }
        Ok(ArtifactResponse::Fresh { body, meta })
    }

    async fn post(&self, req: &PostRequest<'_>) -> Result<Vec<u8>, TransportError> {
        Err(TransportError {
            kind: TransportErrorKind::Other,
            message: format!("files cannot answer a POST to {}", req.url),
            retryable: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use futures_lite::future::block_on;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("ti-pki-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn get(t: &FileTransport, etag: Option<&str>) -> Result<ArtifactResponse, TransportError> {
        block_on(t.get(&ArtifactRequest {
            artifact: Artifact::Tsl,
            url: "",
            etag,
            last_modified: None,
        }))
    }

    fn body_and_etag(r: ArtifactResponse) -> (Vec<u8>, String) {
        match r {
            ArtifactResponse::Fresh { body, meta } => (body, meta.etag.unwrap()),
            ArtifactResponse::NotModified { .. } => panic!("expected a body"),
        }
    }

    #[test]
    fn change_is_detected_and_identical_rewrite_is_not_modified() {
        let dir = TempDir::new("file-change");
        let tsl = dir.0.join("tsl.xml");
        std::fs::write(&tsl, b"v1").unwrap();
        let t = FileTransport::new(dir.0.join("roots.json"), &tsl);

        let (body, etag) = body_and_etag(get(&t, None).unwrap());
        assert_eq!(body, b"v1");
        assert_eq!(etag, content_etag(b"v1"));

        std::fs::write(&tsl, b"v1").unwrap();
        assert!(matches!(
            get(&t, Some(&etag)).unwrap(),
            ArtifactResponse::NotModified { .. }
        ));

        std::fs::write(&tsl, b"v2").unwrap();
        assert_eq!(body_and_etag(get(&t, Some(&etag)).unwrap()).0, b"v2");
    }

    #[test]
    fn missing_file_is_retryable_io() {
        let t = FileTransport::new("/nonexistent/roots.json", "/nonexistent/tsl.xml");
        let error = get(&t, None).unwrap_err();
        assert_eq!(error.kind, TransportErrorKind::Io);
        assert!(error.retryable);
    }

    #[cfg(unix)]
    #[test]
    fn configmap_symlink_swap_is_followed() {
        use std::os::unix::fs::symlink;

        // The layout kubelet writes: timestamped data dirs, a `..data` symlink to the
        // current one, and per-key symlinks through `..data`.
        let dir = TempDir::new("configmap");
        let write_version = |name: &str, content: &[u8]| {
            let version = dir.0.join(name);
            std::fs::create_dir(&version).unwrap();
            std::fs::write(version.join("tsl.xml"), content).unwrap();
        };
        let point_data_at = |name: &str| {
            let tmp = dir.0.join("..data_tmp");
            symlink(name, &tmp).unwrap();
            std::fs::rename(&tmp, dir.0.join("..data")).unwrap();
        };
        write_version("..2026_09_22_1", b"first");
        point_data_at("..2026_09_22_1");
        symlink(Path::new("..data").join("tsl.xml"), dir.0.join("tsl.xml")).unwrap();

        let t = FileTransport::new(dir.0.join("roots.json"), dir.0.join("tsl.xml"));
        assert_eq!(body_and_etag(get(&t, None).unwrap()).0, b"first");

        write_version("..2026_09_22_2", b"second");
        point_data_at("..2026_09_22_2");
        assert_eq!(body_and_etag(get(&t, None).unwrap()).0, b"second");
    }
}
