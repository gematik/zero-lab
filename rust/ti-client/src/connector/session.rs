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

//! A Konnektor ready for calls, and what every call on a card needs: the card found by
//! its identifier, the user ID of its card session, and the Konnektor's refusal for a
//! restricted card type told apart.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use ti_cache::{Cache, CachePolicy, Meta};
use ti_connector_client::model;
use ti_connector_client::types::Card;
use ti_connector_client::{
    ComfortUserId, Connector, Dotkon, PinType, Timeouts, Transport, has_user_sessions,
    is_restricted,
};
use ti_types::Timestamp;

use crate::FileCache;
use crate::block_on;
use crate::connector::UreqTransport;
use crate::error::Error;
use crate::files::{create_private_dir, path_component, write_atomic};
use crate::watch::Watched;

/// A Konnektor ready for calls, by default over the transport a
/// [`Client`](crate::Client) makes ([`Client::connector`](crate::Client::connector)).
pub struct Session<T = Watched<UreqTransport>> {
    /// The Konnektor.
    pub connector: Connector<T>,
    /// Its configuration.
    pub dotkon: Dotkon,
    /// The configuration's name, e.g. `default`.
    pub name: String,
    /// The profile's state directory, which keeps the HBAs' user IDs.
    pub state_dir: PathBuf,
    /// A user ID for every call on an HBA, in place of the kept one; not checked yet.
    pub comfort_user_id: Option<String>,
}

/// The Konnektor of `dotkon` over `transport`, its service directory loaded, through
/// `cache` when given; with where the directory came from then.
///
/// # Errors
///
/// [`Error::Connector`] when the service directory can be neither loaded nor served from
/// the cache.
pub fn connect<T: Transport>(
    dotkon: &Dotkon,
    transport: T,
    timeouts: Timeouts,
    cache: Option<FileCache>,
) -> Result<(Connector<T>, Option<Meta>), Error> {
    match cache {
        None => Ok((
            block_on(Connector::connect(dotkon, transport, timeouts)).map_err(Error::Connector)?,
            None,
        )),
        Some(store) => {
            let cache = Cache::new(store, Timestamp::now, CachePolicy::default());
            let (connector, meta) = block_on(Connector::connect_cached(
                dotkon, transport, timeouts, &cache,
            ))
            .map_err(Error::Connector)?;
            Ok((connector, Some(meta)))
        }
    }
}

/// What a call waits for at the card terminal: the front end shows it while the call
/// blocks, which may take the card timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt {
    /// The user enters the PIN.
    EnterPin(PinType),
    /// The user changes the PIN.
    ChangePin(PinType),
    /// A qualified signature: the user enters PIN.QES.
    SignWithPin,
    /// The card signs; no PIN entry is expected.
    Sign,
    /// The card decrypts.
    Decrypt,
    /// The user enters PIN.QES to activate comfort signature.
    ActivateComfort,
}

/// A wait at the card terminal: what for, which card, and the signature job the
/// terminal shows.
#[derive(Clone, Copy, Debug)]
pub struct Wait<'a> {
    /// What the user is asked to do, or what the card does.
    pub prompt: Prompt,
    /// The card.
    pub card: &'a model::Card,
    /// The job number of a signature, which the terminal shows at PIN entry.
    pub job_number: Option<&'a str>,
}

/// Runs a Konnektor call.
pub(crate) fn call<R>(
    future: impl Future<Output = Result<R, ti_connector_client::Error>>,
) -> Result<R, Error> {
    block_on(future).map_err(Error::Connector)
}

/// Runs a call about `card`; a refusal for a card type the Konnektor restricts on its
/// SOAP API says so.
pub(crate) fn card_call<R>(
    card: &Card,
    future: impl Future<Output = Result<R, ti_connector_client::Error>>,
) -> Result<R, Error> {
    block_on(future).map_err(|error| match error {
        error @ ti_connector_client::Error::Fault(_) if is_restricted(card.card_type) => {
            Error::CardRestricted {
                card_type: card.card_type.to_string(),
                source: error,
            }
        }
        error => Error::Connector(error),
    })
}

/// The card `identifier` names: a handle, an ICCSN or a Telematik-ID.
///
/// # Errors
///
/// [`Error::Connector`].
pub fn find<T: Transport>(session: &Session<T>, identifier: &str) -> Result<Card, Error> {
    call(session.connector.cards().find(identifier))
}

/// The user ID for every call on `card`, in place of the `.kon` file's when `Some`: one
/// ID per HBA ([`has_user_sessions`]). The session's own ID goes first, then the kept
/// one, as activating comfort signature keeps its ID there; deactivating removes it,
/// which brings back the `.kon` file's or makes a new one (TAB_KON_510 C16). Other cards
/// have no such sessions.
///
/// # Errors
///
/// [`Error::ComfortUserIdInvalid`] for a session ID that is no UUID, [`Error::State`] for a
/// kept ID that cannot be read or kept, [`Error::Randomness`].
pub fn card_user<T: Transport>(
    session: &Session<T>,
    card: &Card,
) -> Result<Option<ComfortUserId>, Error> {
    if !has_user_sessions(card.card_type) {
        return Ok(None);
    }
    if let Some(text) = session.comfort_user_id.as_deref() {
        return ComfortUserId::parse(text)
            .map(Some)
            .ok_or(Error::ComfortUserIdInvalid);
    }
    let store = UserIdStore::of(session);
    if let Some(user) = store.load(card)? {
        return Ok(Some(user));
    }
    if session.dotkon.user_id.is_some() {
        return Ok(None);
    }
    let user = new_user_id()?;
    store.save(card, &user)?;
    Ok(Some(user))
}

/// A new user ID from the system's randomness.
pub(crate) fn new_user_id() -> Result<ComfortUserId, Error> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| Error::Randomness)?;
    Ok(ComfortUserId::generate(|b| *b = bytes))
}

/// The user ID of each HBA, one private file under `hba-user/<Konnektor>/<card>` in the
/// profile's state directory. An ID lets anyone with the same call context use what its
/// session has unlocked: sign without a PIN in comfort signature, or a card whose PIN was
/// entered. So the files and the directories above them are for the user alone. A file
/// does not say comfort signature is on: only the Konnektor knows.
pub(crate) struct UserIdStore {
    root: PathBuf,
    dir: PathBuf,
}

impl UserIdStore {
    pub(crate) fn of<T>(session: &Session<T>) -> Self {
        let root = session.state_dir.join("hba-user");
        let dir = root.join(path_component(&session.name));
        UserIdStore { root, dir }
    }

    /// Keyed by ICCSN: a card handle changes when the card is inserted again. The
    /// Konnektor supplies both, so the file name is `path_component` of it.
    fn card_id(card: &Card) -> &str {
        card.iccsn.as_deref().unwrap_or(&card.card_handle)
    }

    fn path(&self, card: &Card) -> PathBuf {
        self.dir.join(path_component(Self::card_id(card)))
    }

    /// Creates the directories and checks them. Activating runs it before the card is
    /// asked: a PIN entered for an ID that cannot be kept would be wasted.
    pub(crate) fn prepare(&self) -> Result<(), Error> {
        // Before creating anything: a symlinked `hba-user/` must not take the new
        // directory to wherever it points.
        private_dir_exists(&self.root)?;
        private_dir_exists(&self.dir)?;
        create_private_dir(&self.dir).map_err(|e| state_error(&self.dir, e))?;
        check_private_dir(&self.root)?;
        check_private_dir(&self.dir)
    }

    /// Whether the directories exist, after checking them: everything that reads or
    /// deletes a file goes through it, so no path is followed through a symlink.
    pub(crate) fn check(&self) -> Result<bool, Error> {
        for dir in [&self.root, &self.dir] {
            if !private_dir_exists(dir)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn load(&self, card: &Card) -> Result<Option<ComfortUserId>, Error> {
        if !self.check()? {
            return Ok(None);
        }
        read_comfort(&self.path(card))
    }

    pub(crate) fn save(&self, card: &Card, user: &ComfortUserId) -> Result<(), Error> {
        self.prepare()?;
        let path = self.path(card);
        write_atomic(&path, user.as_str().as_bytes()).map_err(|e| state_error(&path, e))
    }

    pub(crate) fn remove(&self, card: &Card) -> Result<(), Error> {
        if !self.check()? {
            return Ok(());
        }
        let path = self.path(card);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(state_error(&path, e)),
        }
    }
}

fn state_error(path: &Path, reason: impl std::fmt::Display) -> Error {
    Error::State {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

/// Whether `dir` exists, after checking that it is a real directory only the user can
/// enter.
fn private_dir_exists(dir: &Path) -> Result<bool, Error> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => check_private_dir_meta(dir, &meta).map(|()| true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(state_error(dir, e)),
    }
}

fn check_private_dir(dir: &Path) -> Result<(), Error> {
    let meta = std::fs::symlink_metadata(dir).map_err(|e| state_error(dir, e))?;
    check_private_dir_meta(dir, &meta)
}

/// A symlink is refused, not followed: it could lead the ID out of the user's own
/// directories. A wider mode is refused rather than repaired, since only the user knows
/// who else was meant to have access.
fn check_private_dir_meta(dir: &Path, meta: &std::fs::Metadata) -> Result<(), Error> {
    if meta.file_type().is_symlink() {
        return Err(state_error(
            dir,
            "is a symbolic link; user IDs are kept in real directories only",
        ));
    }
    if !meta.is_dir() {
        return Err(state_error(dir, "is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(state_error(
                dir,
                format!("is open to other users (mode {mode:03o}); run `chmod 700` on it"),
            ));
        }
    }
    Ok(())
}

/// The ID in `path`: none if there is no file. A symlink, a file other users can open
/// and content that is not a user ID are refused, so a file a crash or another process
/// left behind never becomes a session ID.
fn read_comfort(path: &Path) -> Result<Option<ComfortUserId>, Error> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(state_error(path, e)),
    };
    if meta.file_type().is_symlink() {
        return Err(state_error(
            path,
            "is a symbolic link; user IDs are kept in regular files only",
        ));
    }
    if !meta.is_file() {
        return Err(state_error(path, "is not a regular file"));
    }
    let mut file = std::fs::File::open(path).map_err(|e| state_error(path, e))?;
    #[cfg(unix)]
    check_opened(
        path,
        &meta,
        &file.metadata().map_err(|e| state_error(path, e))?,
    )?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|e| state_error(path, e))?;
    ComfortUserId::parse(text.trim()).map(Some).ok_or_else(|| {
        state_error(
            path,
            "does not hold a user ID; remove it and activate again",
        )
    })
}

/// The file opened must be the one checked, or a swap between the two steps would make
/// the checks say nothing about what is read. The mode is taken from the open file.
#[cfg(unix)]
fn check_opened(
    path: &Path,
    checked: &std::fs::Metadata,
    opened: &std::fs::Metadata,
) -> Result<(), Error> {
    use std::os::unix::fs::MetadataExt as _;
    if (checked.dev(), checked.ino()) != (opened.dev(), opened.ino()) {
        return Err(state_error(path, "changed while it was being opened"));
    }
    let mode = opened.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(state_error(
            path,
            format!("is open to other users (mode {mode:03o}); run `chmod 600` on it"),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_file_other_than_the_one_checked_is_refused() {
        let dir = std::env::temp_dir().join(format!("ti-opened-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (checked, swapped) = (dir.join("checked"), dir.join("swapped"));
        std::fs::write(&checked, "a").unwrap();
        std::fs::write(&swapped, "b").unwrap();
        let meta = |path: &Path| std::fs::metadata(path).unwrap();
        for path in [&checked, &swapped] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(check_opened(&checked, &meta(&checked), &meta(&checked)).is_ok());
        let Err(error) = check_opened(&checked, &meta(&checked), &meta(&swapped)) else {
            panic!("another file was opened");
        };
        assert!(error.to_string().contains("changed"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
