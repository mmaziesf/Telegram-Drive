//! Session-store journeys for the native end-to-end suite.
//!
//! The project keeps regression coverage at process boundaries, so these
//! scenarios run inside the native e2e driver and are started by
//! `tests/native_e2e.rs`. Each one works in its own directory with its own
//! key store and key cache, so none touches the desktop credential store.
//! A journey returns a description of the first broken expectation instead of
//! panicking.

use std::fmt::Debug;
use std::path::{Path, PathBuf};

use grammers_session::storages::SqliteSession;
use grammers_session::types::{
    ChannelState, DcOption, PeerAuth, PeerId, PeerInfo, UpdateState, UpdatesState,
};
use grammers_session::Session;
use zeroize::Zeroizing;

use super::format::{self, Contents, FormatError, Header, KdfParams, KeySource};
use super::keys::{
    keychain_reachable, DirectoryKeyStore, KeyCache, KeyError, KeyStore, NoKeyStore,
};
use super::state::{Change, State, MAX_USER_ID};
use super::*;
use crate::crypto::secret::SecretKey;

/// A journey checks one behavior and reports the first broken expectation.
type Journey = fn(&Path) -> Result<(), String>;

/// Every journey, by the name the native e2e suite uses to start it.
pub(crate) const JOURNEYS: &[(&str, Journey)] = &[
    (
        "sealed_round_trip_hides_plaintext",
        sealed_round_trip_hides_plaintext,
    ),
    (
        "every_write_uses_a_fresh_nonce",
        every_write_uses_a_fresh_nonce,
    ),
    ("wrong_key_is_rejected", wrong_key_is_rejected),
    (
        "any_modified_byte_is_rejected",
        any_modified_byte_is_rejected,
    ),
    ("truncated_files_are_rejected", truncated_files_are_rejected),
    (
        "contents_are_classified_without_a_key",
        contents_are_classified_without_a_key,
    ),
    (
        "self_identity_survives_a_peer_refresh",
        self_identity_survives_a_peer_refresh,
    ),
    (
        "out_of_range_peers_are_ignored",
        out_of_range_peers_are_ignored,
    ),
    (
        "update_state_follows_memory_session",
        update_state_follows_memory_session,
    ),
    (
        "snapshots_round_trip_and_reject_ambiguity",
        snapshots_round_trip_and_reject_ambiguity,
    ),
    (
        "keychain_keys_are_random_cached_and_reloaded",
        keychain_keys_are_random_cached_and_reloaded,
    ),
    (
        "passphrase_keys_are_derived_on_demand",
        passphrase_keys_are_derived_on_demand,
    ),
    (
        "unreachable_keychain_is_reported",
        unreachable_keychain_is_reported,
    ),
    (
        "new_session_is_sealed_and_reopens",
        new_session_is_sealed_and_reopens,
    ),
    (
        "deferred_changes_are_written_on_drop",
        deferred_changes_are_written_on_drop,
    ),
    (
        "passphrase_is_chosen_then_required",
        passphrase_is_chosen_then_required,
    ),
    (
        "plaintext_session_is_migrated_and_erased",
        plaintext_session_is_migrated_and_erased,
    ),
    (
        "interrupted_migration_completes_or_rolls_back",
        interrupted_migration_completes_or_rolls_back,
    ),
    (
        "torn_write_is_recovered_from_the_journal",
        torn_write_is_recovered_from_the_journal,
    ),
    ("modified_session_is_rejected", modified_session_is_rejected),
    (
        "missing_or_unreachable_keys_are_distinct",
        missing_or_unreachable_keys_are_distinct,
    ),
    (
        "signed_out_session_stops_writing",
        signed_out_session_stops_writing,
    ),
    (
        "destroy_removes_every_copy_and_the_key",
        destroy_removes_every_copy_and_the_key,
    ),
];

/// Run the named journey in `directory`, which must be empty or absent.
pub(crate) fn run(name: &str, directory: &Path) -> Result<(), String> {
    let journey = JOURNEYS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, journey)| *journey)
        .ok_or_else(|| format!("Unknown session-store journey {name}"))?;
    std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    journey(directory).map_err(|failure| format!("{name}: {failure}"))
}

fn ensure(condition: bool, expectation: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(expectation.to_owned())
    }
}

fn same<T: PartialEq + Debug>(actual: T, expected: T, what: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{what}: expected {expected:?}, got {actual:?}"))
    }
}

fn step<T, E: Debug>(result: Result<T, E>, what: &str) -> Result<T, String> {
    result.map_err(|error| format!("{what}: {error:?}"))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// --- Sealed file format ---------------------------------------------------

fn keychain_header() -> Header {
    Header {
        key_id: [7; 16],
        source: KeySource::Keychain,
    }
}

fn passphrase_header() -> Header {
    Header {
        key_id: [9; 16],
        source: KeySource::Passphrase(KdfParams {
            salt: [3; 16],
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }),
    }
}

fn sealed_round_trip_hides_plaintext(_: &Path) -> Result<(), String> {
    let key = SecretKey::new([1; 32]);
    let plaintext = b"{\"auth_key\":\"secret material\"}";
    for header in [keychain_header(), passphrase_header()] {
        let sealed = step(format::seal(&header, &key, plaintext), "seal")?;
        ensure(
            !contains(&sealed, b"secret material"),
            "plaintext is visible",
        )?;
        same(
            format::inspect(&sealed),
            Contents::Sealed(header),
            "inspect",
        )?;
        let (opened, decrypted) = step(format::open(&sealed, &key), "open")?;
        same(opened, header, "header")?;
        same(decrypted.as_slice(), plaintext.as_slice(), "plaintext")?;
    }
    Ok(())
}

fn every_write_uses_a_fresh_nonce(_: &Path) -> Result<(), String> {
    let key = SecretKey::new([1; 32]);
    let first = step(format::seal(&keychain_header(), &key, b"same"), "seal")?;
    let second = step(format::seal(&keychain_header(), &key, b"same"), "seal")?;
    ensure(first != second, "two writes produced identical ciphertext")
}

fn wrong_key_is_rejected(_: &Path) -> Result<(), String> {
    let sealed = step(
        format::seal(&keychain_header(), &SecretKey::new([1; 32]), b"data"),
        "seal",
    )?;
    same(
        format::open(&sealed, &SecretKey::new([2; 32])).err(),
        Some(FormatError::Authentication),
        "open with the wrong key",
    )
}

fn any_modified_byte_is_rejected(_: &Path) -> Result<(), String> {
    let key = SecretKey::new([1; 32]);
    let sealed = step(
        format::seal(&passphrase_header(), &key, b"session snapshot"),
        "seal",
    )?;
    for index in format::MAGIC.len()..sealed.len() {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        ensure(
            format::open(&tampered, &key).is_err(),
            &format!("byte {index} was not authenticated"),
        )?;
    }
    Ok(())
}

fn truncated_files_are_rejected(_: &Path) -> Result<(), String> {
    let key = SecretKey::new([1; 32]);
    let sealed = step(
        format::seal(&keychain_header(), &key, b"session snapshot"),
        "seal",
    )?;
    for len in 0..sealed.len() {
        ensure(
            format::open(&sealed[..len], &key).is_err(),
            &format!("length {len} was accepted"),
        )?;
    }
    Ok(())
}

fn contents_are_classified_without_a_key(_: &Path) -> Result<(), String> {
    same(format::inspect(b""), Contents::Empty, "empty file")?;
    same(
        format::inspect(b"SQLite format 3\0rest of page"),
        Contents::LegacySqlite,
        "SQLite file",
    )?;
    same(
        format::inspect(b"not a session"),
        Contents::Unrecognized,
        "unknown bytes",
    )?;
    let mut unknown_source = step(
        format::seal(&keychain_header(), &SecretKey::new([1; 32]), b"x"),
        "seal",
    )?;
    unknown_source[format::MAGIC.len()] = 9;
    same(
        format::inspect(&unknown_source),
        Contents::Unrecognized,
        "unknown key source",
    )
}

// --- In-memory session state ----------------------------------------------

fn user(id: i64, is_self: Option<bool>) -> PeerInfo {
    PeerInfo::User {
        id,
        auth: Some(PeerAuth::from_hash(5)),
        bot: Some(false),
        is_self,
    }
}

fn self_identity_survives_a_peer_refresh(_: &Path) -> Result<(), String> {
    let mut state = State::default();
    same(
        state.cache_peer(&user(101, Some(true))),
        Change::Critical,
        "first self",
    )?;
    same(state.owner(), Some(101), "owner")?;
    same(state.cache_peer(&user(101, None)), Change::None, "refresh")?;
    same(
        state.peer(PeerId::self_user()),
        Some(user(101, Some(true))),
        "self after refresh",
    )?;
    same(
        state.cache_peer(&user(202, Some(true))),
        Change::Critical,
        "new self",
    )?;
    same(state.owner(), Some(202), "new owner")?;
    let previous = PeerInfo::User {
        id: 101,
        auth: None,
        bot: None,
        is_self: None,
    };
    same(
        state.peer(previous.id()),
        Some(user(101, Some(false))),
        "previous self",
    )?;
    same(
        state.cache_peer(&user(202, Some(false))),
        Change::Critical,
        "self cleared",
    )?;
    same(state.owner(), None, "owner after clear")
}

fn out_of_range_peers_are_ignored(_: &Path) -> Result<(), String> {
    let mut state = State::default();
    for peer in [
        PeerInfo::User {
            id: 0,
            auth: None,
            bot: None,
            is_self: Some(true),
        },
        PeerInfo::User {
            id: MAX_USER_ID + 1,
            auth: None,
            bot: None,
            is_self: None,
        },
        PeerInfo::Chat { id: -4 },
        PeerInfo::Channel {
            id: 998_000_000_000,
            auth: None,
            kind: None,
        },
    ] {
        same(state.cache_peer(&peer), Change::None, "out-of-range peer")?;
    }
    ensure(state.peers.is_empty(), "an out-of-range peer was cached")?;
    same(state.owner(), None, "owner")
}

fn update_state_follows_memory_session(_: &Path) -> Result<(), String> {
    let mut state = State::default();
    same(
        state.set_update_state(UpdateState::Primary {
            pts: 1,
            date: 2,
            seq: 3,
        }),
        Change::Deferred,
        "primary",
    )?;
    same(
        state.set_update_state(UpdateState::Secondary { qts: 4 }),
        Change::Deferred,
        "secondary",
    )?;
    state.set_update_state(UpdateState::Channel { id: 9, pts: 1 });
    state.set_update_state(UpdateState::Channel { id: 9, pts: 2 });
    same(
        &state.updates,
        &UpdatesState {
            pts: 1,
            qts: 4,
            date: 2,
            seq: 3,
            channels: vec![ChannelState { id: 9, pts: 2 }],
        },
        "updates",
    )?;
    same(
        state.set_update_state(UpdateState::Channel { id: 9, pts: 2 }),
        Change::None,
        "repeated channel state",
    )
}

fn snapshots_round_trip_and_reject_ambiguity(_: &Path) -> Result<(), String> {
    let mut state = State::default();
    state.set_home_dc(4);
    let mut option = state
        .dc_options
        .get(&4)
        .cloned()
        .ok_or("DC 4 is not known")?;
    option.auth_key = Some([7; 256]);
    state.set_dc_option(&option);
    state.cache_peer(&user(101, Some(true)));
    state.cache_peer(&PeerInfo::Channel {
        id: 55,
        auth: Some(PeerAuth::from_hash(-3)),
        kind: None,
    });
    state.set_update_state(UpdateState::Channel { id: 55, pts: 8 });
    let bytes = step(state.to_bytes(), "serialize")?;
    same(
        &step(State::from_bytes(&bytes), "parse")?,
        &state,
        "round trip",
    )?;

    let two_selves = format!(
        "{{\"version\":1,\"home_dc\":2,\"dc_options\":[],\"peers\":[{},{}],\"updates\":{}}}",
        json(&user(1, Some(true)))?,
        json(&user(2, Some(true)))?,
        json(&UpdatesState::default())?,
    );
    ensure(
        State::from_bytes(two_selves.as_bytes()).is_err(),
        "a snapshot with two selves was accepted",
    )?;
    ensure(
        State::from_bytes(b"{\"version\":2}").is_err(),
        "an unknown snapshot version was accepted",
    )
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

// --- Session keys ----------------------------------------------------------

fn same_key(left: &SecretKey, right: &SecretKey) -> bool {
    left.expose() == right.expose()
}

fn keychain_keys_are_random_cached_and_reloaded(dir: &Path) -> Result<(), String> {
    let store = DirectoryKeyStore(dir.join("keys"));
    let cache = KeyCache::default();
    let (header, key) = step(cache.new_key(Some(&store)), "new key")?;
    same(&header.source, &KeySource::Keychain, "key source")?;
    let (_, other) = step(cache.new_key(Some(&store)), "second key")?;
    ensure(!same_key(&key, &other), "two new keys are equal")?;

    let reloaded = step(KeyCache::default().key_for(&header, Some(&store)), "reload")?;
    ensure(same_key(&reloaded, &key), "the reloaded key differs")?;
    step(store.delete(&header.key_name()), "delete")?;
    let cached = step(cache.key_for(&header, Some(&store)), "cached")?;
    ensure(same_key(&cached, &key), "the cached key differs")?;
    same(
        KeyCache::default().key_for(&header, Some(&store)).err(),
        Some(KeyError::KeyMissing),
        "deleted key",
    )
}

fn passphrase_keys_are_derived_on_demand(_: &Path) -> Result<(), String> {
    let cache = KeyCache::default();
    same(
        cache.new_key(Some(&NoKeyStore)).err(),
        Some(KeyError::PassphraseRequired),
        "new key without a passphrase",
    )?;
    cache.set_passphrase(Zeroizing::new("correct horse battery".into()));
    let (header, key) = step(cache.new_key(Some(&NoKeyStore)), "passphrase key")?;
    ensure(
        matches!(header.source, KeySource::Passphrase(_)),
        "the key is not passphrase-derived",
    )?;

    // The same passphrase derives the same key in a later process.
    let later = KeyCache::default();
    same(
        later.key_for(&header, None).err(),
        Some(KeyError::PassphraseRequired),
        "later key without a passphrase",
    )?;
    later.set_passphrase(Zeroizing::new("correct horse battery".into()));
    let derived = step(later.key_for(&header, None), "derive")?;
    ensure(
        same_key(&derived, &key),
        "the same passphrase derived another key",
    )?;

    let wrong = KeyCache::default();
    wrong.set_passphrase(Zeroizing::new("another passphrase".into()));
    let other = step(wrong.key_for(&header, None), "derive")?;
    ensure(
        !same_key(&other, &key),
        "another passphrase derived the same key",
    )
}

fn unreachable_keychain_is_reported(_: &Path) -> Result<(), String> {
    let header = Header {
        key_id: [1; 16],
        source: KeySource::Keychain,
    };
    ensure(
        matches!(
            KeyCache::default().key_for(&header, Some(&NoKeyStore)),
            Err(KeyError::KeychainUnavailable(_))
        ),
        "an unreachable keychain was not reported",
    )?;
    ensure(
        !keychain_reachable(Some(&NoKeyStore)),
        "an unreachable store was reported reachable",
    )?;
    ensure(!keychain_reachable(None), "no store was reported reachable")
}

// --- Sealed session files -------------------------------------------------

const PASSPHRASE: &str = "correct horse battery staple";

/// One session file with its own key store and in-memory key cache.
struct Fixture {
    dir: PathBuf,
    store: DirectoryKeyStore,
    cache: KeyCache,
}

impl Fixture {
    fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            store: DirectoryKeyStore(dir.join("keys")),
            cache: KeyCache::default(),
        }
    }

    fn session_path(&self) -> PathBuf {
        self.dir.join("telegram.session")
    }

    /// A placeholder like the one `session_protection` creates before a login.
    fn placeholder(&self) -> Result<PathBuf, String> {
        let path = self.session_path();
        step(std::fs::write(&path, b""), "placeholder")?;
        Ok(path)
    }

    fn open(&self) -> Result<SealedSession, String> {
        step(
            open_with(&self.session_path(), Some(&self.store), &self.cache),
            "open",
        )
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
        std::fs::read_dir(self.dir.join("keys")).map_or(0, |entries| entries.count())
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

fn authorized_dc(id: i32, byte: u8) -> Result<DcOption, String> {
    let mut option = State::default()
        .dc_options
        .get(&id)
        .cloned()
        .ok_or_else(|| format!("DC {id} is not known"))?;
    option.auth_key = Some([byte; 256]);
    Ok(option)
}

/// Write a session the way earlier releases did: a SQLite file by grammers.
fn write_legacy(path: &Path) -> Result<(), String> {
    let session = step(SqliteSession::open(path), "legacy session")?;
    session.set_home_dc_id(4);
    session.set_dc_option(&authorized_dc(4, 0xAB)?);
    session.cache_peer(&me(101));
    session.cache_peer(&contact(555));
    Ok(())
}

fn owner_after_reopen(fixture: &Fixture) -> Result<Option<i64>, String> {
    Ok(step(fixture.reopen(), "reopen")?.owner())
}

fn new_session_is_sealed_and_reopens(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        step(
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)),
            "chmod",
        )?;
    }
    {
        let session = fixture.open()?;
        session.set_dc_option(&authorized_dc(2, 0xCD)?);
        session.cache_peer(&me(101));
        session.cache_peer(&contact(555));
        ensure(session.flush(), "flush failed")?;
    }
    let bytes = step(std::fs::read(&path), "read")?;
    ensure(bytes.starts_with(format::MAGIC), "the file is not sealed")?;
    ensure(
        !contains(&bytes, &[0xCD; 32]),
        "authorization key is visible on disk",
    )?;
    same(fixture.stored_keys(), 1, "stored keys")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = step(std::fs::metadata(&path), "metadata")?
            .permissions()
            .mode();
        same(mode & 0o777, 0o600, "file mode")?;
    }

    let session = step(fixture.reopen(), "reopen")?;
    same(session.owner(), Some(101), "owner")?;
    same(
        session.dc_option(2).and_then(|option| option.auth_key),
        Some([0xCD; 256]),
        "authorization key",
    )?;
    same(session.peer(PeerId::self_user()), Some(me(101)), "self")?;
    same(
        session.peer(contact(555).id()),
        Some(contact(555)),
        "contact",
    )?;
    same(
        read_owner_with(&path, Some(&fixture.store), &KeyCache::default()),
        Ok(Some(101)),
        "owner without opening",
    )
}

fn deferred_changes_are_written_on_drop(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    fixture.placeholder()?;
    fixture.open()?.cache_peer(&contact(777));
    let session = step(fixture.reopen(), "reopen")?;
    same(
        session.peer(contact(777).id()),
        Some(contact(777)),
        "contact",
    )
}

fn passphrase_is_chosen_then_required(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    let cache = KeyCache::default();
    let status = |cache: &KeyCache| status_with(&path, Some(&NoKeyStore), cache);
    let open = |cache: &KeyCache| open_with(&path, Some(&NoKeyStore), cache);
    let unlock = |passphrase: &str, cache: &KeyCache| {
        unlock_with(&path, Zeroizing::new(passphrase.to_owned()), cache)
    };
    let rejected = |result: Result<(), String>, code: &str| match result {
        Err(message) if message.starts_with(code) => Ok(()),
        other => Err(format!("expected {code}, got {other:?}")),
    };
    same(
        status(&cache),
        StorageStatus {
            protection: "passphrase",
            locked: true,
            setup: true,
        },
        "first status",
    )?;
    same(
        open(&cache).err(),
        Some(SessionOpenError::Locked { setup: true }),
        "open before setup",
    )?;
    rejected(unlock("short", &cache), "SESSION_PASSPHRASE_TOO_SHORT:")?;
    step(unlock(PASSPHRASE, &cache), "choose passphrase")?;
    step(open(&cache), "open after setup")?.cache_peer(&me(101));

    // A later process has no passphrase until the user enters it again.
    let later = KeyCache::default();
    same(
        status(&later),
        StorageStatus {
            protection: "passphrase",
            locked: true,
            setup: false,
        },
        "later status",
    )?;
    same(
        open(&later).err(),
        Some(SessionOpenError::Locked { setup: false }),
        "open while locked",
    )?;
    rejected(
        unlock("not the passphrase", &later),
        "SESSION_PASSPHRASE_INCORRECT:",
    )?;
    step(unlock(PASSPHRASE, &later), "unlock")?;
    same(
        step(open(&later), "open after unlock")?.owner(),
        Some(101),
        "owner",
    )
}

fn plaintext_session_is_migrated_and_erased(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.session_path();
    write_legacy(&path)?;
    let wal = files::sibling(&path, "-wal");
    step(std::fs::write(&wal, [0xAB; 64]), "sidecar")?;
    same(
        read_owner_with(&path, Some(&fixture.store), &fixture.cache),
        Ok(Some(101)),
        "legacy owner",
    )?;
    {
        let session = fixture.open()?;
        same(session.owner(), Some(101), "owner")?;
        same(session.home_dc_id(), 4, "home DC")?;
        same(
            session.dc_option(4).and_then(|option| option.auth_key),
            Some([0xAB; 256]),
            "authorization key",
        )?;
        same(
            session.peer(contact(555).id()).map(|peer| peer.id()),
            Some(contact(555).id()),
            "contact",
        )?;
    }
    let bytes = step(std::fs::read(&path), "read")?;
    ensure(bytes.starts_with(format::MAGIC), "the file is not sealed")?;
    ensure(
        !contains(&bytes, b"SQLite format 3"),
        "SQLite header survived",
    )?;
    ensure(!contains(&bytes, &[0xAB; 32]), "authorization key survived")?;
    ensure(!wal.exists(), "the SQLite sidecar survived")?;
    ensure(
        !files::sibling(&path, STAGING).exists(),
        "the staging copy survived",
    )?;
    same(
        owner_after_reopen(&fixture)?,
        Some(101),
        "owner after reopen",
    )
}

fn interrupted_migration_completes_or_rolls_back(dir: &Path) -> Result<(), String> {
    // Interrupted after the plaintext was wiped: the staged copy wins.
    let fixture = Fixture::new(&dir.join("wiped"));
    step(std::fs::create_dir_all(&fixture.dir), "directory")?;
    let path = fixture.session_path();
    write_legacy(&path)?;
    let state = step(legacy::import(&path), "import")?;
    let (header, key) = step(fixture.cache.new_key(Some(&fixture.store)), "key")?;
    let sealed = step(seal_state(&header, &key, &state), "seal")?;
    step(
        std::fs::write(files::sibling(&path, STAGING), &sealed),
        "staging",
    )?;
    step(files::overwrite(&path), "wipe")?;
    same(fixture.open()?.owner(), Some(101), "finished migration")?;
    ensure(
        !files::sibling(&path, STAGING).exists(),
        "the staging copy survived",
    )?;

    // Interrupted while the staged copy was written, before the plaintext was
    // touched: the migration restarts and the unused key is removed.
    let fixture = Fixture::new(&dir.join("partial"));
    step(std::fs::create_dir_all(&fixture.dir), "directory")?;
    let path = fixture.session_path();
    write_legacy(&path)?;
    let (header, key) = step(fixture.cache.new_key(Some(&fixture.store)), "key")?;
    let sealed = step(seal_state(&header, &key, &State::default()), "seal")?;
    step(
        std::fs::write(files::sibling(&path, STAGING), &sealed[..sealed.len() - 1]),
        "partial staging",
    )?;
    same(fixture.stored_keys(), 1, "keys before restart")?;
    same(fixture.open()?.owner(), Some(101), "restarted migration")?;
    ensure(
        matches!(fixture.store.load(&header.key_name()), Ok(None)),
        "the unused key was kept",
    )?;
    same(fixture.stored_keys(), 1, "keys after restart")
}

fn torn_write_is_recovered_from_the_journal(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    fixture.open()?.cache_peer(&me(101));
    let good = step(std::fs::read(&path), "read")?;
    let journal = files::sibling(&path, JOURNAL);

    // The journal was flushed, then the rewrite of the main file was torn.
    step(std::fs::write(&journal, &good), "journal")?;
    step(std::fs::write(&path, &good[..good.len() / 2]), "torn")?;
    same(owner_after_reopen(&fixture)?, Some(101), "recovered owner")?;
    same(
        step(std::fs::read(&path), "read")?,
        good.clone(),
        "recovered file",
    )?;
    ensure(!journal.exists(), "the journal survived recovery")?;

    // A torn journal beside an intact main file is discarded.
    step(std::fs::write(&journal, &good[..10]), "torn journal")?;
    same(owner_after_reopen(&fixture)?, Some(101), "owner")?;
    ensure(!journal.exists(), "the torn journal survived")
}

fn modified_session_is_rejected(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    fixture.open()?.cache_peer(&me(101));
    let mut bytes = step(std::fs::read(&path), "read")?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    step(std::fs::write(&path, &bytes), "tamper")?;
    ensure(
        matches!(fixture.reopen(), Err(SessionOpenError::Unreadable(_))),
        "a modified session was opened",
    )?;
    step(
        std::fs::write(&path, b"neither SQLite nor sealed"),
        "garbage",
    )?;
    ensure(
        matches!(fixture.reopen(), Err(SessionOpenError::Unreadable(_))),
        "an unrecognized file was opened",
    )
}

fn missing_or_unreachable_keys_are_distinct(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    fixture.open()?.cache_peer(&me(101));
    ensure(
        matches!(
            open_with(&path, Some(&NoKeyStore), &KeyCache::default()),
            Err(SessionOpenError::KeychainUnavailable(_))
        ),
        "an unreachable keychain was not reported",
    )?;
    step(std::fs::remove_dir_all(dir.join("keys")), "drop keys")?;
    ensure(
        matches!(fixture.reopen(), Err(SessionOpenError::Unreadable(_))),
        "a missing key was not reported as unreadable",
    )
}

fn signed_out_session_stops_writing(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    let old = fixture.open()?;
    old.cache_peer(&me(101));
    destroy_with(&path, Some(&fixture.store), &fixture.cache);
    ensure(!path.exists(), "the session survived sign-out")?;
    same(fixture.stored_keys(), 0, "keys after sign-out")?;
    // A late write must not bring the signed-out session back.
    old.set_dc_option(&authorized_dc(2, 0x11)?);
    ensure(!path.exists(), "a late write restored the session")?;

    // A new sign-in at the same path is not overwritten by the old session.
    fixture.placeholder()?;
    let new = fixture.open()?;
    new.cache_peer(&me(202));
    old.set_dc_option(&authorized_dc(2, 0x22)?);
    old.cache_peer(&me(101));
    drop(old);
    drop(new);
    same(
        owner_after_reopen(&fixture)?,
        Some(202),
        "owner of the new sign-in",
    )
}

fn destroy_removes_every_copy_and_the_key(dir: &Path) -> Result<(), String> {
    let fixture = Fixture::new(dir);
    let path = fixture.placeholder()?;
    fixture.open()?.cache_peer(&me(101));
    let bytes = step(std::fs::read(&path), "read")?;
    for suffix in [JOURNAL, STAGING, "-wal", "-shm", "-journal"] {
        step(
            std::fs::write(files::sibling(&path, suffix), &bytes),
            "copy",
        )?;
    }
    destroy_with(&path, Some(&fixture.store), &fixture.cache);
    for suffix in ["", JOURNAL, STAGING, "-wal", "-shm", "-journal"] {
        ensure(
            !files::sibling(&path, suffix).exists(),
            &format!("{suffix:?} survived"),
        )?;
    }
    same(fixture.stored_keys(), 0, "keys after destroy")
}
