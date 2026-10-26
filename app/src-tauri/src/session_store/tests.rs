//! Tests for the sealed session store. Each test uses its own directory, key
//! store and key cache, so none of them touches the desktop credential store.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use grammers_session::storages::SqliteSession;
use grammers_session::types::{DcOption, PeerAuth, PeerId, PeerInfo};
use grammers_session::Session;
use zeroize::Zeroizing;

use super::keys::{DirectoryKeyStore, KeyCache, KeyStore, NoKeyStore};
use super::*;

/// A unique directory under the system temporary directory, removed on drop.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "session-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const PASSPHRASE: &str = "correct horse battery staple";

struct Fixture {
    dir: TestDir,
    store: DirectoryKeyStore,
    cache: KeyCache,
}

impl Fixture {
    fn new() -> Self {
        let dir = TestDir::new();
        let store = DirectoryKeyStore(dir.path().join("keys"));
        Self {
            dir,
            store,
            cache: KeyCache::default(),
        }
    }

    fn session_path(&self) -> PathBuf {
        self.dir.path().join("telegram.session")
    }

    /// A placeholder like the one `session_protection` creates before a login.
    fn placeholder(&self) -> PathBuf {
        let path = self.session_path();
        std::fs::write(&path, b"").expect("placeholder");
        path
    }

    fn open(&self) -> Result<SealedSession, SessionOpenError> {
        open_with(&self.session_path(), Some(&self.store), &self.cache)
    }

    /// Open as a later process would: nothing cached in memory.
    fn reopen(&self) -> Result<SealedSession, SessionOpenError> {
        open_with(
            &self.session_path(),
            Some(&self.store),
            &KeyCache::default(),
        )
    }

    fn stored_keys(&self) -> usize {
        std::fs::read_dir(self.dir.path().join("keys")).map_or(0, |entries| entries.count())
    }
}

fn me(id: i64) -> PeerInfo {
    PeerInfo::User {
        id,
        auth: Some(PeerAuth::from_hash(7)),
        bot: Some(false),
        is_self: Some(true),
    }
}

fn contact(id: i64) -> PeerInfo {
    PeerInfo::User {
        id,
        auth: Some(PeerAuth::from_hash(9)),
        bot: Some(false),
        is_self: None,
    }
}

fn authorized_dc(id: i32, byte: u8) -> DcOption {
    let mut option = State::default()
        .dc_options
        .get(&id)
        .cloned()
        .expect("known DC");
    option.auth_key = Some([byte; 256]);
    option
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Write a session the way earlier releases did: a SQLite file by grammers.
fn write_legacy(path: &Path) {
    let session = SqliteSession::open(path).expect("legacy session");
    session.set_home_dc_id(4);
    session.set_dc_option(&authorized_dc(4, 0xAB));
    session.cache_peer(&me(101));
    session.cache_peer(&contact(555));
}

#[test]
fn a_new_session_is_sealed_with_a_keychain_key_and_reopens() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    {
        let session = fixture.open().expect("open");
        session.set_dc_option(&authorized_dc(2, 0xCD));
        session.cache_peer(&me(101));
        session.cache_peer(&contact(555));
        assert!(session.flush());
    }
    let bytes = std::fs::read(&path).expect("read");
    assert!(bytes.starts_with(format::MAGIC));
    assert!(
        !contains(&bytes, &[0xCD; 32]),
        "authorization key is visible on disk"
    );
    assert_eq!(fixture.stored_keys(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let session = fixture.reopen().expect("reopen");
    assert_eq!(session.owner(), Some(101));
    assert_eq!(
        session.dc_option(2).and_then(|option| option.auth_key),
        Some([0xCD; 256])
    );
    assert_eq!(session.peer(PeerId::self_user()), Some(me(101)));
    assert_eq!(session.peer(contact(555).id()), Some(contact(555)));
    assert_eq!(
        read_owner_with(&path, Some(&fixture.store), &KeyCache::default()),
        Ok(Some(101))
    );
}

#[test]
fn deferred_changes_are_written_when_the_session_is_dropped() {
    let fixture = Fixture::new();
    fixture.placeholder();
    {
        let session = fixture.open().expect("open");
        session.cache_peer(&contact(777));
    }
    let session = fixture.reopen().expect("reopen");
    assert_eq!(session.peer(contact(777).id()), Some(contact(777)));
}

#[test]
fn without_a_keychain_a_passphrase_is_chosen_and_then_required() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    let cache = KeyCache::default();
    assert_eq!(
        status_with(&path, Some(&NoKeyStore), &cache),
        StorageStatus {
            protection: "passphrase",
            locked: true,
            setup: true
        }
    );
    assert_eq!(
        open_with(&path, Some(&NoKeyStore), &cache).err(),
        Some(SessionOpenError::Locked { setup: true })
    );
    assert!(unlock_with(&path, Zeroizing::new("short".into()), &cache)
        .unwrap_err()
        .starts_with("SESSION_PASSPHRASE_TOO_SHORT:"));
    unlock_with(&path, Zeroizing::new(PASSPHRASE.into()), &cache).expect("choose passphrase");
    {
        let session = open_with(&path, Some(&NoKeyStore), &cache).expect("open");
        session.cache_peer(&me(101));
    }

    // A later process has no passphrase until the user enters it again.
    let later = KeyCache::default();
    assert_eq!(
        status_with(&path, Some(&NoKeyStore), &later),
        StorageStatus {
            protection: "passphrase",
            locked: true,
            setup: false
        }
    );
    assert_eq!(
        open_with(&path, Some(&NoKeyStore), &later).err(),
        Some(SessionOpenError::Locked { setup: false })
    );
    assert!(
        unlock_with(&path, Zeroizing::new("not the passphrase".into()), &later)
            .unwrap_err()
            .starts_with("SESSION_PASSPHRASE_INCORRECT:")
    );
    unlock_with(&path, Zeroizing::new(PASSPHRASE.into()), &later).expect("unlock");
    let session = open_with(&path, Some(&NoKeyStore), &later).expect("open");
    assert_eq!(session.owner(), Some(101));
}

#[test]
fn a_plaintext_session_is_migrated_and_the_original_is_erased() {
    let fixture = Fixture::new();
    let path = fixture.session_path();
    write_legacy(&path);
    let wal = files::sibling(&path, "-wal");
    std::fs::write(&wal, [0xAB; 64]).expect("sidecar");
    assert_eq!(
        read_owner_with(&path, Some(&fixture.store), &fixture.cache),
        Ok(Some(101))
    );

    let session = fixture.open().expect("migrate");
    assert_eq!(session.owner(), Some(101));
    assert_eq!(session.home_dc_id(), 4);
    assert_eq!(
        session.dc_option(4).and_then(|option| option.auth_key),
        Some([0xAB; 256])
    );
    assert_eq!(
        session.peer(contact(555).id()).map(|peer| peer.id()),
        Some(contact(555).id())
    );
    drop(session);

    let bytes = std::fs::read(&path).expect("read");
    assert!(bytes.starts_with(format::MAGIC));
    assert!(!contains(&bytes, b"SQLite format 3"));
    assert!(!contains(&bytes, &[0xAB; 32]));
    assert!(!wal.exists());
    assert!(!files::sibling(&path, STAGING).exists());
    assert_eq!(fixture.reopen().expect("reopen").owner(), Some(101));
}

#[test]
fn an_interrupted_migration_is_completed_or_rolled_back() {
    // Interrupted after the plaintext was wiped: the staged copy wins.
    let fixture = Fixture::new();
    let path = fixture.session_path();
    write_legacy(&path);
    let state = legacy::import(&path).expect("import");
    let (header, key) = fixture.cache.new_key(Some(&fixture.store)).expect("key");
    let sealed = seal_state(&header, &key, &state).expect("seal");
    std::fs::write(files::sibling(&path, STAGING), &sealed).expect("staging");
    files::overwrite(&path).expect("wipe");
    assert_eq!(fixture.open().expect("finish").owner(), Some(101));
    assert!(!files::sibling(&path, STAGING).exists());

    // Interrupted while the staged copy was written, before the plaintext was
    // touched: the migration restarts and the unused key is removed.
    let fixture = Fixture::new();
    let path = fixture.session_path();
    write_legacy(&path);
    let (header, key) = fixture.cache.new_key(Some(&fixture.store)).expect("key");
    let sealed = seal_state(&header, &key, &State::default()).expect("seal");
    std::fs::write(files::sibling(&path, STAGING), &sealed[..sealed.len() - 1])
        .expect("partial staging");
    assert_eq!(fixture.stored_keys(), 1);
    assert_eq!(fixture.open().expect("migrate").owner(), Some(101));
    assert!(matches!(fixture.store.load(&header.key_name()), Ok(None)));
    assert_eq!(fixture.stored_keys(), 1);
}

#[test]
fn a_torn_write_is_recovered_from_the_journal() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    let session = fixture.open().expect("open");
    session.cache_peer(&me(101));
    drop(session);
    let good = std::fs::read(&path).expect("read");

    // The journal was flushed, then the rewrite of the main file was torn.
    std::fs::write(files::sibling(&path, JOURNAL), &good).expect("journal");
    std::fs::write(&path, &good[..good.len() / 2]).expect("torn");
    assert_eq!(fixture.reopen().expect("recover").owner(), Some(101));
    assert_eq!(std::fs::read(&path).expect("read"), good);
    assert!(!files::sibling(&path, JOURNAL).exists());

    // A torn journal beside an intact main file is discarded.
    std::fs::write(files::sibling(&path, JOURNAL), &good[..10]).expect("torn journal");
    assert_eq!(fixture.reopen().expect("open").owner(), Some(101));
    assert!(!files::sibling(&path, JOURNAL).exists());
}

#[test]
fn a_modified_session_is_rejected() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    fixture.open().expect("open").cache_peer(&me(101));
    let mut bytes = std::fs::read(&path).expect("read");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, &bytes).expect("tamper");
    assert!(matches!(
        fixture.reopen(),
        Err(SessionOpenError::Unreadable(_))
    ));

    std::fs::write(&path, b"neither SQLite nor sealed").expect("garbage");
    assert!(matches!(
        fixture.reopen(),
        Err(SessionOpenError::Unreadable(_))
    ));
}

#[test]
fn missing_or_unreachable_keys_are_reported_distinctly() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    fixture.open().expect("open").cache_peer(&me(101));
    assert!(matches!(
        open_with(&path, Some(&NoKeyStore), &KeyCache::default()),
        Err(SessionOpenError::KeychainUnavailable(_))
    ));
    std::fs::remove_dir_all(fixture.dir.path().join("keys")).expect("drop keys");
    assert!(matches!(
        fixture.reopen(),
        Err(SessionOpenError::Unreadable(_))
    ));
}

#[test]
fn a_session_stops_writing_once_its_file_is_signed_out_or_replaced() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    let old = fixture.open().expect("open");
    old.cache_peer(&me(101));
    destroy_with(&path, Some(&fixture.store), &fixture.cache);
    assert!(!path.exists());
    assert_eq!(fixture.stored_keys(), 0);
    // A late write must not bring the signed-out session back.
    old.set_dc_option(&authorized_dc(2, 0x11));
    assert!(!path.exists());

    // A new sign-in at the same path is not overwritten by the old session.
    fixture.placeholder();
    let new = fixture.open().expect("new session");
    new.cache_peer(&me(202));
    old.set_dc_option(&authorized_dc(2, 0x22));
    old.cache_peer(&me(101));
    drop(old);
    drop(new);
    assert_eq!(fixture.reopen().expect("reopen").owner(), Some(202));
}

#[test]
fn destroy_removes_every_copy_and_the_key() {
    let fixture = Fixture::new();
    let path = fixture.placeholder();
    fixture.open().expect("open").cache_peer(&me(101));
    let bytes = std::fs::read(&path).expect("read");
    for suffix in [JOURNAL, STAGING, "-wal", "-shm", "-journal"] {
        std::fs::write(files::sibling(&path, suffix), &bytes).expect("copy");
    }
    destroy_with(&path, Some(&fixture.store), &fixture.cache);
    for suffix in ["", JOURNAL, STAGING, "-wal", "-shm", "-journal"] {
        assert!(!files::sibling(&path, suffix).exists(), "{suffix} survived");
    }
    assert_eq!(fixture.stored_keys(), 0);
}
