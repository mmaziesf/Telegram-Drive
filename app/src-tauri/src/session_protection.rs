//! Owner-only protection for the Telegram session database.
//!
//! The session database holds the MTProto authorization keys of the signed-in
//! account. Whoever can read it can act as that account until the session is
//! revoked, so it must never be readable by other local users.
//!
//! On Unix-like systems the account directory is kept at mode 0700 and the
//! session database at mode 0600. The database is created privately before
//! SQLite opens it, because SQLite gives its `-wal`, `-shm` and `-journal`
//! sidecars the mode of the main database. Files written by earlier releases
//! with wider modes are tightened in place the next time the session opens.
//!
//! Windows keeps application data under the per-user profile, whose ACL
//! already excludes other standard users, so the mode changes are no-ops there.

use std::path::{Path, PathBuf};

/// File name of the session database inside an account directory.
pub(crate) const SESSION_FILE_NAME: &str = "telegram.session";

/// SQLite companion files that can hold copies of session pages.
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

#[cfg(unix)]
const OWNER_ONLY_DIRECTORY: u32 = 0o700;
#[cfg(unix)]
const OWNER_ONLY_FILE: u32 = 0o600;

/// Path of the session database for an account directory.
pub(crate) fn session_path(root: &Path) -> PathBuf {
    root.join(SESSION_FILE_NAME)
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Make an account directory and its session database private before the
/// database is opened. Returns the database path.
pub(crate) fn prepare_account_session(root: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(root)?;
    restrict_directory(root)?;
    let database = session_path(root);
    prepare_session_file(&database)?;
    Ok(database)
}

/// Create a session database file privately if it does not exist yet, and
/// tighten an existing database and its SQLite sidecars.
pub(crate) fn prepare_session_file(database: &Path) -> std::io::Result<()> {
    create_private_file(database)?;
    restrict_session_files(database)
}

/// Tighten an existing session database and any SQLite sidecars next to it.
pub(crate) fn restrict_session_files(database: &Path) -> std::io::Result<()> {
    restrict_file(database)?;
    for suffix in SQLITE_SIDECARS {
        restrict_file(&sidecar_path(database, suffix))?;
    }
    Ok(())
}

/// Like [`prepare_account_session`], but a failure is logged rather than
/// returned. Sign-in must keep working on file systems that do not support
/// Unix modes; the warning makes the weaker protection visible in logs.
pub(crate) fn prepare_account_session_or_warn(root: &Path) {
    if let Err(error) = prepare_account_session(root) {
        log::warn!("Could not restrict the Telegram session files to this user: {error}");
    }
}

/// Like [`restrict_session_files`], logging instead of failing.
pub(crate) fn restrict_session_files_or_warn(database: &Path) {
    if let Err(error) = restrict_session_files(database) {
        log::warn!("Could not restrict the Telegram session files to this user: {error}");
    }
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(OWNER_ONLY_FILE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn create_private_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Remove group and other permission bits from a regular file. Symbolic links
/// are left alone so a planted link cannot redirect the mode change.
#[cfg(unix)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 == 0 {
        return Ok(());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY_FILE))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 == 0 {
        return Ok(());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY_DIRECTORY))
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
