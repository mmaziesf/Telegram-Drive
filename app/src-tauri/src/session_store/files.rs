//! File operations for the sealed session: owner-only creation, reads and
//! writes that never follow a planted symbolic link, and best-effort erasure.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Path of a sibling file such as the `.next` journal or a SQLite sidecar.
pub(crate) fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    options
}

/// Read a whole file without following a symbolic link. A missing file is `None`.
pub(crate) fn read(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match options().read(true).open(path) {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(Some(bytes))
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Open an existing file for an in-place rewrite. It is never created, so a
/// session that was signed out is not brought back by a late write.
pub(crate) fn open_existing(path: &Path) -> std::io::Result<File> {
    options().read(true).write(true).open(path)
}

/// Replace the contents of an open file in place, restrict it to its owner
/// and flush it to disk.
pub(crate) fn rewrite(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()
}

/// Create or truncate an owner-only file, write it and flush it to disk.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()
}

/// Flush a directory entry change, such as a rename, to disk.
pub(crate) fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
            log::warn!("Could not flush the session directory: {error}");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Overwrite a file's contents with zeros and flush them, keeping the file.
/// A missing file is not an error.
///
/// This is best effort: on SSDs with wear levelling, copy-on-write or
/// snapshotting file systems, and backups, earlier copies of the bytes can
/// survive. Full-disk encryption is the dependable protection for those.
pub(crate) fn overwrite(path: &Path) -> std::io::Result<()> {
    let mut file = match options().write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let mut remaining = file.metadata()?.len();
    let zeros = [0u8; 64 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()
}

/// [`overwrite`] a file, then remove it. A missing file is not an error.
pub(crate) fn erase(path: &Path) -> std::io::Result<()> {
    overwrite(path)?;
    remove(path)
}

/// Remove a file; a missing file is not an error.
pub(crate) fn remove(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}
