//! Local files a command may read must come from the user (red-team RT-13).
//!
//! Commands such as `cmd_upload_file` take a local path from the WebView. A
//! script running in the WebView could otherwise pass any path the user can
//! read and copy that file into the user's Telegram account or a preview cache.
//!
//! Tauri records every path the user picks in a file dialog, and every path
//! dropped onto the window, by adding it to the asset protocol scope. That
//! happens in Rust before the result reaches the WebView. [`install`] listens
//! for those additions and keeps its own list, so the static asset scope from
//! `tauri.conf.json` (preview and thumbnail caches) is not part of it.
//!
//! A picked or dropped file grants that file. A picked or dropped folder grants
//! everything inside it. Grants last until the app quits; they are not
//! written to disk. Paths are compared after resolving symlinks, so a link
//! inside a granted folder that points outside it is refused.
//!
//! Android and iOS pickers return content URIs that do not go through this
//! scope, so the check is desktop-only there (see RT-11 for the Android path).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// Upper bound on remembered grants; the oldest are dropped first.
pub const MAX_GRANTS: usize = 4096;

/// Error prefix the interface can match on.
pub const NOT_SELECTED: &str = "NOT_SELECTED";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Grant {
    path: PathBuf,
    directory: bool,
}

/// Paths the user picked or dropped during this run of the app.
#[derive(Debug, Default)]
pub struct PathGrants {
    grants: Mutex<Vec<Grant>>,
}

impl PathGrants {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember a path the user chose. Paths that do not exist (for example a
    /// "save as" target) are ignored: there is nothing to read yet.
    pub fn record(&self, path: &Path) {
        let Ok(canonical) = path.canonicalize() else {
            return;
        };
        let directory = canonical.is_dir();
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        grants.retain(|grant| grant.path != canonical);
        grants.push(Grant {
            path: canonical,
            directory,
        });
        if grants.len() > MAX_GRANTS {
            let excess = grants.len() - MAX_GRANTS;
            grants.drain(..excess);
        }
    }

    /// Whether `path` is a granted file or lies inside a granted folder.
    pub fn allows(&self, path: &Path) -> bool {
        let Ok(canonical) = path.canonicalize() else {
            return false;
        };
        let grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        grants.iter().any(|grant| {
            if grant.directory {
                canonical.starts_with(&grant.path)
            } else {
                canonical == grant.path
            }
        })
    }

    /// Number of remembered grants.
    pub fn len(&self) -> usize {
        self.grants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The grants for this process.
pub fn global() -> &'static PathGrants {
    static GRANTS: OnceLock<PathGrants> = OnceLock::new();
    GRANTS.get_or_init(PathGrants::new)
}

/// Start recording dialog picks and window drops.
pub fn install<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use tauri::Manager;
    app.asset_protocol_scope().listen(|event| {
        if let tauri::scope::fs::Event::PathAllowed(path) = event {
            global().record(path);
        }
    });
}

/// The message returned when a path was not chosen by the user.
pub fn not_selected_error() -> String {
    format!(
        "{NOT_SELECTED}: Choose this item again with the file picker or drag it into the window"
    )
}
