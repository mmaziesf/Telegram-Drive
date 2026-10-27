//! Telegram sessions that sign-out could not end.
//!
//! Sign-out ends the Telegram authorization with the session's own key. When
//! that key is gone (a forgotten passphrase, an unreachable credential store)
//! or Telegram does not answer in time, only the local copy is removed and the
//! device stays listed in the account's active sessions. A marker holding the
//! time of that sign-out, and the account when it was known, is kept next to
//! the session. After the next sign-in to that account the app lists its other
//! sessions that use the same API ID and were created before the marker. Nothing is ended automatically: the user
//! selects and confirms each one, and the current session is never eligible.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MARKER: &str = "revocation-pending.json";

/// A sign-out that could not end its Telegram session.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub(crate) struct Pending {
    /// Unix time (seconds) of the sign-out.
    pub since: i64,
    /// Telegram user ID of the signed-out account. Unknown when the session
    /// was locked, in which case any account that signs in next is asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<i64>,
}

impl Pending {
    /// Whether the sessions of `signed_in` may be offered. Another known
    /// account is never shown this marker, and the marker is kept for it.
    pub(crate) fn applies_to(self, signed_in: i64) -> bool {
        self.owner.is_none_or(|owner| owner == signed_in)
    }
}

fn marker_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join(MARKER)
}

/// Records that a sign-out at `now` left its Telegram session active.
/// A later marker replaces an earlier one, because it covers every session
/// the earlier one did.
pub(crate) fn record(app_data_dir: &Path, marker: Pending) {
    let result = serde_json::to_vec(&marker)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            std::fs::write(marker_path(app_data_dir), bytes).map_err(|error| error.to_string())
        });
    if let Err(error) = result {
        log::warn!("Could not record the session left active at sign-out: {error}");
    }
}

/// The time of the sign-out that left a session active, if one is pending.
pub(crate) fn pending(app_data_dir: &Path) -> Option<Pending> {
    let bytes = std::fs::read(marker_path(app_data_dir)).ok()?;
    match serde_json::from_slice::<Pending>(&bytes) {
        Ok(marker) => Some(marker),
        Err(_) => {
            log::warn!("Ignoring a malformed pending-revocation marker");
            None
        }
    }
}

/// Keeps a marker after a sign-out that removed a saved session without
/// Telegram confirming that its authorization ended.
pub(crate) fn after_sign_out(
    app_data_dir: &Path,
    had_session: bool,
    revoked: bool,
    now: i64,
    owner: Option<i64>,
) {
    if had_session && !revoked {
        record(app_data_dir, Pending { since: now, owner });
    }
}

/// Forgets the pending revocation.
pub(crate) fn clear(app_data_dir: &Path) {
    match std::fs::remove_file(marker_path(app_data_dir)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => log::warn!("Could not remove the pending-revocation marker: {error}"),
    }
}

/// One entry of Telegram's active-session list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Authorization {
    pub hash: i64,
    pub current: bool,
    pub api_id: i32,
    pub device_model: String,
    pub platform: String,
    pub system_version: String,
    pub app_name: String,
    pub app_version: String,
    pub date_created: i64,
    pub date_active: i64,
}

/// A session the user may choose to end, as shown in the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleSession {
    /// Telegram's authorization hash, as a string so JavaScript keeps every digit.
    pub id: String,
    pub device: String,
    pub app: String,
    /// Unix time (seconds) the session was last active.
    pub last_active: i64,
}

fn join_nonempty(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The sessions eligible for ending: not the current one, created by the same
/// API ID before the sign-out that left them active. Telegram reports the
/// current session with hash 0, which is excluded as well.
pub(crate) fn stale_sessions(
    authorizations: &[Authorization],
    api_id: i32,
    since: i64,
) -> Vec<StaleSession> {
    authorizations
        .iter()
        .filter(|entry| {
            !entry.current
                && entry.hash != 0
                && entry.api_id == api_id
                && entry.date_created < since
        })
        .map(|entry| StaleSession {
            id: entry.hash.to_string(),
            device: join_nonempty(&[&entry.device_model, &entry.platform, &entry.system_version]),
            app: join_nonempty(&[&entry.app_name, &entry.app_version]),
            last_active: entry.date_active,
        })
        .collect()
}

/// The hashes to end for the sessions the user confirmed. Every confirmed ID
/// must be one of `eligible`; anything else, including the current session,
/// rejects the whole request so nothing unexpected is ended.
pub(crate) fn confirmed_hashes(
    eligible: &[StaleSession],
    confirmed: &[String],
) -> Result<Vec<i64>, String> {
    if confirmed.is_empty() {
        return Err("No session was selected".to_string());
    }
    let mut hashes = Vec::with_capacity(confirmed.len());
    for id in confirmed {
        if !eligible.iter().any(|session| &session.id == id) {
            return Err("A selected session can no longer be ended from this list".to_string());
        }
        let hash = id
            .parse::<i64>()
            .map_err(|_| "A selected session can no longer be ended from this list".to_string())?;
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    Ok(hashes)
}

#[cfg(feature = "native-e2e")]
pub(crate) mod journeys;
