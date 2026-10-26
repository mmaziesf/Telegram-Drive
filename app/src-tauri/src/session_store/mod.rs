//! The Telegram session, encrypted at rest.
//!
//! `telegram.session` holds the account's authorization keys. It is sealed
//! with XChaCha20-Poly1305 under a 256-bit key that lives in the operating
//! system's credential store (Secret Service on Linux, Keychain on macOS,
//! Credential Manager on Windows). Where no credential store is reachable,
//! the key is derived from a passphrase with Argon2id instead.
//!
//! A plaintext SQLite session from an earlier release is imported, sealed and
//! written beside the old file, which is then overwritten with zeros before
//! the sealed copy replaces it. Overwriting is best effort; see
//! [`files::overwrite`].
//!
//! Writes go to a `.next` journal first and then rewrite the session file in
//! place, so a torn write is recovered from the journal on the next start and
//! the file keeps its identity for the account checks in
//! `workspace::account`.

mod files;
mod format;
mod keys;
mod legacy;
mod state;

use std::fmt;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use grammers_session::types::{DcOption, PeerId, PeerInfo, UpdateState, UpdatesState};
use grammers_session::Session;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;
use format::{Contents, Header, KeySource};
use keys::{KeyCache, KeyError, KeyStore};
use state::{Change, State};

/// How long changes that can wait are collected before they are written.
const FLUSH_DELAY: Duration = Duration::from_millis(500);
/// How long to wait before retrying after a failed write.
const RETRY_DELAY: Duration = Duration::from_secs(5);
const JOURNAL: &str = ".next";
const STAGING: &str = ".migrating";
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// Why a session could not be opened. The messages carry a stable code for
/// the frontend and never contain key material.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionOpenError {
    /// A passphrase must be entered first. `setup` is true when no session
    /// exists yet and the passphrase will protect a new one.
    Locked { setup: bool },
    /// The session's key is in a credential store that cannot be reached now.
    KeychainUnavailable(String),
    /// The file exists but cannot be used, even with the right key.
    Unreadable(String),
    /// A file system error that may go away on retry.
    Io(String),
}

impl fmt::Display for SessionOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locked { setup: true } => formatter
                .write_str("SESSION_PASSPHRASE_SETUP: Choose a passphrase to protect your Telegram session"),
            Self::Locked { setup: false } => formatter
                .write_str("SESSION_LOCKED: Enter your passphrase to unlock your Telegram session"),
            Self::KeychainUnavailable(reason) => write!(
                formatter,
                "SESSION_KEYCHAIN_UNAVAILABLE: The system credential store is unavailable ({reason})"
            ),
            Self::Unreadable(reason) => {
                write!(formatter, "SESSION_UNREADABLE: The saved session cannot be read ({reason})")
            }
            Self::Io(reason) => {
                write!(formatter, "SESSION_UNAVAILABLE: The saved session is unavailable ({reason})")
            }
        }
    }
}

impl std::error::Error for SessionOpenError {}

fn io_error(error: std::io::Error) -> SessionOpenError {
    SessionOpenError::Io(error.to_string())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Pending {
    dirty: bool,
    closing: bool,
}

struct Inner {
    path: PathBuf,
    header: Header,
    key: SecretKey,
    state: Mutex<State>,
    pending: Mutex<Pending>,
    wake: Condvar,
    write_lock: Mutex<()>,
    /// Set once the file on disk no longer belongs to this session, for
    /// example after sign-out. A retired session never writes again.
    retired: AtomicBool,
}

impl Inner {
    /// Write the current state. Errors are logged and the write is retried
    /// later; they never contain key material.
    fn persist(&self) -> bool {
        if self.retired.load(Ordering::SeqCst) {
            return true;
        }
        let _writer = lock(&self.write_lock);
        lock(&self.pending).dirty = false;
        match self.write_snapshot() {
            Ok(()) => true,
            Err(error) => {
                lock(&self.pending).dirty = true;
                log::warn!("Could not save the Telegram session: {error}");
                false
            }
        }
    }

    fn retire(&self, reason: &str) {
        if !self.retired.swap(true, Ordering::SeqCst) {
            log::info!("Stopped saving a Telegram session: {reason}");
        }
    }

    fn write_snapshot(&self) -> Result<(), String> {
        let plaintext = lock(&self.state).to_bytes().map_err(|error| error.0)?;
        let sealed = format::seal(&self.header, &self.key, &plaintext)
            .map_err(|_| "the session could not be encrypted".to_string())?;
        // The file is never created here: a session that was signed out must
        // not come back because a late write was still queued.
        let mut file = match files::open_existing(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                self.retire("the session file was removed");
                return Ok(());
            }
            Err(error) => return Err(error.to_string()),
        };
        let mut current = Vec::new();
        file.read_to_end(&mut current)
            .map_err(|error| error.to_string())?;
        if format::peek_header(&current).map(|header| header.key_id) != Some(self.header.key_id) {
            self.retire("the session file now belongs to another sign-in");
            return Ok(());
        }
        let journal = files::sibling(&self.path, JOURNAL);
        files::write_private(&journal, &sealed).map_err(|error| error.to_string())?;
        files::rewrite(&mut file, &sealed).map_err(|error| error.to_string())?;
        files::remove(&journal).map_err(|error| error.to_string())
    }
}

fn run_flusher(inner: Arc<Inner>) {
    let mut delay = FLUSH_DELAY;
    loop {
        {
            let pending = lock(&inner.pending);
            let pending = inner
                .wake
                .wait_while(pending, |pending| !pending.dirty && !pending.closing)
                .unwrap_or_else(PoisonError::into_inner);
            if pending.closing {
                return;
            }
            // Collect further changes for a short while before writing.
            let (pending, _) = inner
                .wake
                .wait_timeout_while(pending, delay, |pending| !pending.closing)
                .unwrap_or_else(PoisonError::into_inner);
            if pending.closing {
                return;
            }
        }
        delay = if inner.persist() {
            FLUSH_DELAY
        } else {
            RETRY_DELAY
        };
    }
}

/// A grammers [`Session`] stored in a sealed file.
///
/// Authorization keys, the home DC and the account identity are written
/// before the setter returns. Other changes, such as the peer cache and
/// update state, are written by a background thread shortly afterwards and
/// when the session is dropped.
pub struct SealedSession {
    inner: Arc<Inner>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

impl SealedSession {
    fn new(path: &Path, header: Header, key: SecretKey, state: State) -> Self {
        let inner = Arc::new(Inner {
            path: path.to_path_buf(),
            header,
            key,
            state: Mutex::new(state),
            pending: Mutex::new(Pending::default()),
            wake: Condvar::new(),
            write_lock: Mutex::new(()),
            retired: AtomicBool::new(false),
        });
        let worker = inner.clone();
        let flusher = std::thread::Builder::new()
            .name("session-flush".into())
            .spawn(move || run_flusher(worker))
            .map_err(|error| {
                log::warn!("Session changes will be saved synchronously: {error}");
            })
            .ok();
        Self {
            inner,
            flusher: Mutex::new(flusher),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.inner.state)
    }

    fn record(&self, change: Change) {
        match change {
            Change::None => {}
            Change::Deferred if lock(&self.flusher).is_some() => {
                lock(&self.inner.pending).dirty = true;
                self.inner.wake.notify_all();
            }
            Change::Deferred | Change::Critical => {
                self.inner.persist();
            }
        }
    }

    /// Write pending changes now. Returns whether the state on disk is current.
    pub(crate) fn flush(&self) -> bool {
        self.inner.persist()
    }

    /// The signed-in account's user id, if the session has one.
    pub(crate) fn owner(&self) -> Option<i64> {
        self.state().owner()
    }
}

impl Drop for SealedSession {
    fn drop(&mut self) {
        lock(&self.inner.pending).closing = true;
        self.inner.wake.notify_all();
        if let Some(handle) = lock(&self.flusher).take() {
            if handle.join().is_err() {
                log::warn!("The session flush thread stopped unexpectedly");
            }
        }
        if lock(&self.inner.pending).dirty {
            self.inner.persist();
        }
    }
}

impl Session for SealedSession {
    fn home_dc_id(&self) -> i32 {
        self.state().home_dc
    }

    fn set_home_dc_id(&self, dc_id: i32) {
        let change = self.state().set_home_dc(dc_id);
        self.record(change);
    }

    fn dc_option(&self, dc_id: i32) -> Option<DcOption> {
        self.state().dc_options.get(&dc_id).cloned()
    }

    fn set_dc_option(&self, dc_option: &DcOption) {
        let change = self.state().set_dc_option(dc_option);
        self.record(change);
    }

    fn peer(&self, peer: PeerId) -> Option<PeerInfo> {
        self.state().peer(peer)
    }

    fn cache_peer(&self, peer: &PeerInfo) {
        let change = self.state().cache_peer(peer);
        self.record(change);
    }

    fn updates_state(&self) -> UpdatesState {
        self.state().updates.clone()
    }

    fn set_update_state(&self, update: UpdateState) {
        let change = self.state().set_update_state(update);
        self.record(change);
    }
}

/// Decrypt and parse sealed bytes.
fn decrypt(bytes: &[u8], key: &SecretKey) -> Result<(Header, State), String> {
    let (header, plaintext) =
        format::open(bytes, key).map_err(|_| "the session failed authentication".to_string())?;
    let state = State::from_bytes(&plaintext).map_err(|error| error.0)?;
    Ok((header, state))
}

fn erase_or_warn(path: &Path) {
    if let Err(error) = files::erase(path) {
        log::warn!("Could not erase a leftover session file: {error}");
        if let Err(error) = files::remove(path) {
            log::warn!("Could not remove a leftover session file: {error}");
        }
    }
}

fn erase_sidecars(path: &Path) {
    for suffix in SQLITE_SIDECARS {
        erase_or_warn(&files::sibling(path, suffix));
    }
}

/// Complete or undo a migration that an earlier run did not finish.
fn finish_migration(path: &Path, store: Option<&dyn KeyStore>) {
    let staging = files::sibling(path, STAGING);
    let Ok(Some(staged)) = files::read(&staging) else {
        return;
    };
    let main_is_legacy = matches!(
        files::read(path)
            .ok()
            .flatten()
            .as_deref()
            .map(format::inspect),
        Some(Contents::LegacySqlite)
    );
    let header = format::peek_header(&staged);
    match header {
        // The staged copy was flushed before the old file was touched, so a
        // valid staged copy beside a wiped or missing original is complete.
        Some(_) if !main_is_legacy => {
            match std::fs::rename(&staging, path) {
                Ok(()) => {
                    files::sync_directory(path);
                    log::info!("Completed an interrupted move of the Telegram session to encrypted storage");
                }
                Err(error) => log::warn!("Could not complete the session migration: {error}"),
            }
        }
        _ => {
            if let (
                Some(Header {
                    key_id,
                    source: KeySource::Keychain,
                }),
                Some(store),
            ) = (header, store)
            {
                let name = Header {
                    key_id,
                    source: KeySource::Keychain,
                }
                .key_name();
                if let Err(error) = store.delete(&name) {
                    log::warn!("Could not remove an unused session key: {}", error.0);
                }
            }
            erase_or_warn(&staging);
        }
    }
}

fn new_key_error(error: KeyError) -> SessionOpenError {
    match error {
        KeyError::PassphraseRequired => SessionOpenError::Locked { setup: true },
        KeyError::KeychainUnavailable(reason) => SessionOpenError::KeychainUnavailable(reason),
        KeyError::KeyMissing | KeyError::Derivation => {
            SessionOpenError::Io("a session key could not be created".into())
        }
    }
}

fn existing_key_error(error: KeyError) -> SessionOpenError {
    match error {
        KeyError::PassphraseRequired => SessionOpenError::Locked { setup: false },
        KeyError::KeychainUnavailable(reason) => SessionOpenError::KeychainUnavailable(reason),
        KeyError::KeyMissing => {
            SessionOpenError::Unreadable("its key is no longer in the credential store".into())
        }
        KeyError::Derivation => {
            SessionOpenError::Unreadable("its key parameters are not supported".into())
        }
    }
}

type Opened = (Header, SecretKey, State);

fn seal_state(
    header: &Header,
    key: &SecretKey,
    state: &State,
) -> Result<Vec<u8>, SessionOpenError> {
    let plaintext = state
        .to_bytes()
        .map_err(|error| SessionOpenError::Io(error.0))?;
    format::seal(header, key, &plaintext)
        .map_err(|_| SessionOpenError::Io("the session could not be encrypted".into()))
}

/// Seal an empty placeholder in place, as long as it is still empty.
fn create(
    path: &Path,
    store: Option<&dyn KeyStore>,
    cache: &KeyCache,
) -> Result<Opened, SessionOpenError> {
    let state = State::default();
    let (header, key) = cache.new_key(store).map_err(new_key_error)?;
    let sealed = seal_state(&header, &key, &state)?;
    let mut file = files::open_existing(path).map_err(io_error)?;
    let mut current = Vec::new();
    file.read_to_end(&mut current).map_err(io_error)?;
    if !current.is_empty() {
        return Err(SessionOpenError::Io(
            "the session file changed while it was created".into(),
        ));
    }
    files::rewrite(&mut file, &sealed).map_err(io_error)?;
    Ok((header, key, state))
}

/// Seal a plaintext SQLite session and wipe the original.
fn migrate(
    path: &Path,
    store: Option<&dyn KeyStore>,
    cache: &KeyCache,
) -> Result<Opened, SessionOpenError> {
    let state = legacy::import(path).map_err(|error| SessionOpenError::Unreadable(error.0))?;
    let (header, key) = cache.new_key(store).map_err(new_key_error)?;
    let sealed = seal_state(&header, &key, &state)?;
    let staging = files::sibling(path, STAGING);
    files::write_private(&staging, &sealed).map_err(io_error)?;
    files::overwrite(path).map_err(io_error)?;
    for suffix in SQLITE_SIDECARS {
        files::overwrite(&files::sibling(path, suffix)).map_err(io_error)?;
    }
    std::fs::rename(&staging, path).map_err(io_error)?;
    files::sync_directory(path);
    log::info!("Moved the Telegram session to encrypted storage and erased the plaintext copy");
    Ok((header, key, state))
}

/// Open a sealed session, recovering from the journal after a torn write.
fn open_sealed(
    path: &Path,
    main: &[u8],
    store: Option<&dyn KeyStore>,
    cache: &KeyCache,
) -> Result<Opened, SessionOpenError> {
    let journal_path = files::sibling(path, JOURNAL);
    let journal = files::read(&journal_path).map_err(io_error)?;
    let journal_header = journal.as_deref().and_then(format::peek_header);
    let header = format::peek_header(main)
        .or(journal_header)
        .ok_or_else(|| {
            SessionOpenError::Unreadable("it is not a recognized session format".into())
        })?;
    let key = cache.key_for(&header, store).map_err(existing_key_error)?;

    // A journal is removed only after the main file was rewritten and
    // flushed, so a journal that opens is never older than the main file.
    if let (Some(bytes), Some(found)) = (journal.as_deref(), journal_header) {
        if found.key_id == header.key_id {
            if let Ok((opened, state)) = decrypt(bytes, &key) {
                let mut file = files::open_existing(path).map_err(io_error)?;
                files::rewrite(&mut file, bytes).map_err(io_error)?;
                files::remove(&journal_path).map_err(io_error)?;
                log::info!("Completed an interrupted Telegram session write from its journal");
                return Ok((opened, key, state));
            }
        }
    }
    if let Ok((opened, state)) = decrypt(main, &key) {
        if journal.is_some() {
            // A journal that does not open was itself torn mid-write.
            files::remove(&journal_path).map_err(io_error)?;
        }
        return Ok((opened, key, state));
    }
    cache.forget(&header);
    if matches!(header.source, KeySource::Passphrase(_)) {
        // A wrong passphrase looks the same as a modified file. Ask again
        // rather than discarding a session that may be intact.
        cache.clear_passphrase();
        return Err(SessionOpenError::Locked { setup: false });
    }
    Err(SessionOpenError::Unreadable(
        "it failed authentication".into(),
    ))
}

fn open_with(
    path: &Path,
    store: Option<&dyn KeyStore>,
    cache: &KeyCache,
) -> Result<SealedSession, SessionOpenError> {
    finish_migration(path, store);
    let bytes = files::read(path)
        .map_err(io_error)?
        .ok_or_else(|| SessionOpenError::Io("the session file is missing".into()))?;
    let (header, key, state) = match format::inspect(&bytes) {
        Contents::Empty => create(path, store, cache)?,
        Contents::LegacySqlite => migrate(path, store, cache)?,
        Contents::Sealed(_) | Contents::Unrecognized => open_sealed(path, &bytes, store, cache)?,
    };
    erase_sidecars(path);
    Ok(SealedSession::new(path, header, key, state))
}

/// Open the session at `path`, creating, migrating or recovering it as needed.
/// The file must exist; an empty file starts a new session.
pub(crate) fn open(path: &Path) -> Result<SealedSession, SessionOpenError> {
    let store = keys::key_store();
    open_with(path, Some(store.as_ref()), KeyCache::global())
}

/// Every sealed copy of the session that may exist, with its unverified header.
fn sealed_copies(path: &Path) -> Vec<(Vec<u8>, Header)> {
    [
        path.to_path_buf(),
        files::sibling(path, JOURNAL),
        files::sibling(path, STAGING),
    ]
    .iter()
    .filter_map(|candidate| files::read(candidate).ok().flatten())
    .filter_map(|bytes| format::peek_header(&bytes).map(|header| (bytes, header)))
    .collect()
}

fn read_owner_with(
    path: &Path,
    store: Option<&dyn KeyStore>,
    cache: &KeyCache,
) -> Result<Option<i64>, String> {
    let bytes = files::read(path)
        .map_err(|error| error.to_string())?
        .ok_or("the session file is missing")?;
    match format::inspect(&bytes) {
        Contents::Empty => Ok(None),
        Contents::LegacySqlite => legacy::read_owner(path).map_err(|error| error.0),
        Contents::Sealed(_) | Contents::Unrecognized => {
            for (bytes, header) in sealed_copies(path) {
                let key = cache
                    .key_for(&header, store)
                    .map_err(|error| format!("{error:?}"))?;
                if let Ok((_, state)) = decrypt(&bytes, &key) {
                    return Ok(state.owner());
                }
            }
            Err("the session cannot be read".into())
        }
    }
}

/// The account id stored in the session at `path`, without opening it for
/// writing. `None` means no account has signed in yet.
pub(crate) fn read_owner(path: &Path) -> Result<Option<i64>, String> {
    let store = keys::key_store();
    read_owner_with(path, Some(store.as_ref()), KeyCache::global())
}

/// How the session is protected, for the unlock screen.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatus {
    /// `keychain` or `passphrase`.
    pub protection: &'static str,
    /// A passphrase must be entered before the session can open.
    pub locked: bool,
    /// The passphrase will protect a new session, so it must be chosen.
    pub setup: bool,
}

fn status_with(path: &Path, store: Option<&dyn KeyStore>, cache: &KeyCache) -> StorageStatus {
    let existing = sealed_copies(path)
        .into_iter()
        .next()
        .map(|(_, header)| header.source);
    match existing {
        Some(KeySource::Keychain) => StorageStatus {
            protection: "keychain",
            locked: false,
            setup: false,
        },
        Some(KeySource::Passphrase(_)) => StorageStatus {
            protection: "passphrase",
            locked: !cache.has_passphrase(),
            setup: false,
        },
        None if keys::keychain_reachable(store) => StorageStatus {
            protection: "keychain",
            locked: false,
            setup: false,
        },
        None => StorageStatus {
            protection: "passphrase",
            locked: !cache.has_passphrase(),
            setup: true,
        },
    }
}

/// How the session at `path` is protected and whether it needs a passphrase.
pub(crate) fn status(path: &Path) -> StorageStatus {
    let store = keys::key_store();
    status_with(path, Some(store.as_ref()), KeyCache::global())
}

fn unlock_with(path: &Path, passphrase: Zeroizing<String>, cache: &KeyCache) -> Result<(), String> {
    let copies: Vec<_> = sealed_copies(path)
        .into_iter()
        .filter_map(|(bytes, header)| match header.source {
            KeySource::Passphrase(params) => Some((bytes, header, params)),
            KeySource::Keychain => None,
        })
        .collect();
    if copies.is_empty() {
        if sealed_copies(path).is_empty() {
            if passphrase.chars().count() < keys::MIN_PASSPHRASE_CHARS {
                return Err(format!(
                    "SESSION_PASSPHRASE_TOO_SHORT: Use at least {} characters",
                    keys::MIN_PASSPHRASE_CHARS
                ));
            }
            cache.set_passphrase(passphrase);
        }
        return Ok(());
    }
    for (bytes, header, params) in copies {
        let key = keys::derive(&passphrase, &params).map_err(|_| {
            "SESSION_UNREADABLE: The session's key parameters are not supported".to_string()
        })?;
        if format::open(&bytes, &key).is_ok() {
            cache.remember(&header, &key);
            cache.set_passphrase(passphrase);
            return Ok(());
        }
    }
    Err("SESSION_PASSPHRASE_INCORRECT: The passphrase is incorrect".into())
}

/// Enter the passphrase for a passphrase-protected session, or choose one
/// for a new session when no credential store is available. Argon2id runs on
/// a blocking thread.
pub(crate) async fn unlock(path: PathBuf, passphrase: String) -> Result<(), String> {
    let passphrase = Zeroizing::new(passphrase);
    tokio::task::spawn_blocking(move || unlock_with(&path, passphrase, KeyCache::global()))
        .await
        .map_err(|_| "SESSION_UNAVAILABLE: Unlocking was interrupted".to_string())?
}

fn destroy_with(path: &Path, store: Option<&dyn KeyStore>, cache: &KeyCache) {
    for (_, header) in sealed_copies(path) {
        cache.forget(&header);
        if let (KeySource::Keychain, Some(store)) = (header.source, store) {
            if let Err(error) = store.delete(&header.key_name()) {
                log::warn!(
                    "Could not remove the session key from the credential store: {}",
                    error.0
                );
            }
        }
    }
    for suffix in ["", JOURNAL, STAGING] {
        erase_or_warn(&files::sibling(path, suffix));
    }
    erase_sidecars(path);
}

/// Sign-out: remove the session's key from the credential store and erase
/// the session file, its journal and any leftovers. A live [`SealedSession`]
/// for the file stops writing once it notices the file is gone.
pub(crate) fn destroy(path: &Path) {
    let store = keys::key_store();
    destroy_with(path, Some(store.as_ref()), KeyCache::global());
}

/// Keep native end-to-end runs off the desktop credential store.
#[cfg(feature = "native-e2e")]
pub(crate) fn use_directory_key_store(directory: PathBuf) {
    keys::install_key_store(Arc::new(keys::DirectoryKeyStore(directory)));
}

#[cfg(feature = "native-e2e")]
pub(crate) mod journeys;
