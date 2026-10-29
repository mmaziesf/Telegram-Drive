//! In-memory session contents and their serialized snapshot.

use std::collections::HashMap;

use grammers_session::types::{
    ChannelState, DcOption, PeerId, PeerInfo, UpdateState, UpdatesState,
};
use grammers_session::SessionData;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Largest Telegram user id (Bot API user ids are positive and fit in 40 bits).
pub(crate) const MAX_USER_ID: i64 = 0xff_ffff_ffff;
const SNAPSHOT_VERSION: u32 = 1;

/// The key a peer is cached under, or `None` for an id outside every range
/// grammers accepts. grammers panics on such ids, so they are never passed on.
pub(crate) fn peer_key(info: &PeerInfo) -> Option<PeerId> {
    let valid = match *info {
        PeerInfo::User { id, .. } => (1..=MAX_USER_ID).contains(&id),
        PeerInfo::Chat { id } => (1..=999_999_999_999).contains(&id),
        PeerInfo::Channel { id, .. } => {
            (1..=997_852_516_352).contains(&id)
                || (1_002_147_483_649..=3_000_000_000_000).contains(&id)
        }
    };
    valid.then(|| info.id())
}

fn is_self(info: &PeerInfo) -> bool {
    matches!(
        info,
        PeerInfo::User {
            is_self: Some(true),
            ..
        }
    )
}

/// How urgently a change must reach the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Change {
    /// Nothing changed.
    None,
    /// Can be written together with later changes.
    Deferred,
    /// Authorization keys, the home DC and the account identity are written
    /// before the call returns, so a crash cannot lose a login.
    Critical,
}

/// Everything a Telegram session stores.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct State {
    pub home_dc: i32,
    pub dc_options: HashMap<i32, DcOption>,
    pub peers: HashMap<PeerId, PeerInfo>,
    pub self_peer: Option<PeerId>,
    pub updates: UpdatesState,
}

impl Default for State {
    fn default() -> Self {
        let defaults = SessionData::default();
        Self {
            home_dc: defaults.home_dc,
            dc_options: defaults.dc_options,
            peers: HashMap::new(),
            self_peer: None,
            updates: UpdatesState::default(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    version: u32,
    home_dc: i32,
    dc_options: Vec<DcOption>,
    peers: Vec<PeerInfo>,
    updates: UpdatesState,
}

/// A snapshot that cannot be used.
#[derive(Debug)]
pub(crate) struct SnapshotError(pub String);

impl State {
    /// Serialize for sealing. The buffer is wiped when dropped.
    ///
    /// `serde_json` builds the text in a growing buffer, so intermediate
    /// copies of the authorization keys can remain in freed heap memory.
    pub(crate) fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, SnapshotError> {
        let snapshot = Snapshot {
            version: SNAPSHOT_VERSION,
            home_dc: self.home_dc,
            dc_options: self.dc_options.values().cloned().collect(),
            peers: self.peers.values().cloned().collect(),
            updates: self.updates.clone(),
        };
        serde_json::to_vec(&snapshot)
            .map(Zeroizing::new)
            .map_err(|error| SnapshotError(error.to_string()))
    }

    /// Parse a decrypted snapshot, rejecting ids grammers cannot represent and
    /// ambiguous account identities.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|error| SnapshotError(error.to_string()))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(SnapshotError(format!(
                "unsupported snapshot version {}",
                snapshot.version
            )));
        }
        let mut state = State {
            home_dc: snapshot.home_dc,
            dc_options: State::default().dc_options,
            peers: HashMap::new(),
            self_peer: None,
            updates: snapshot.updates,
        };
        for option in snapshot.dc_options {
            state.dc_options.insert(option.id, option);
        }
        for peer in snapshot.peers {
            state
                .insert_imported(peer)
                .map_err(|error| SnapshotError(error.0))?;
        }
        Ok(state)
    }

    /// Add a stored peer. A second account identity is an error rather than
    /// a guess about which one is current.
    pub(crate) fn insert_imported(
        &mut self,
        info: PeerInfo,
    ) -> Result<(), super::legacy::LegacyError> {
        let key = peer_key(&info)
            .ok_or_else(|| super::legacy::LegacyError("cached peer id is out of range".into()))?;
        if is_self(&info) {
            if self.self_peer.is_some_and(|current| current != key) {
                return Err(super::legacy::LegacyError(
                    "session has more than one account identity".into(),
                ));
            }
            self.self_peer = Some(key);
        }
        self.peers.insert(key, info);
        Ok(())
    }

    /// The signed-in account's user id, if the session has one.
    pub(crate) fn owner(&self) -> Option<i64> {
        match self.self_peer.and_then(|key| self.peers.get(&key)) {
            Some(PeerInfo::User {
                id,
                is_self: Some(true),
                ..
            }) => Some(*id),
            _ => None,
        }
    }

    pub(crate) fn set_home_dc(&mut self, dc_id: i32) -> Change {
        if self.home_dc == dc_id {
            return Change::None;
        }
        self.home_dc = dc_id;
        Change::Critical
    }

    pub(crate) fn set_dc_option(&mut self, option: &DcOption) -> Change {
        if self.dc_options.get(&option.id) == Some(option) {
            return Change::None;
        }
        self.dc_options.insert(option.id, option.clone());
        Change::Critical
    }

    pub(crate) fn peer(&self, peer: PeerId) -> Option<PeerInfo> {
        if peer == PeerId::self_user() {
            self.self_peer.and_then(|key| self.peers.get(&key)).cloned()
        } else {
            self.peers.get(&peer).cloned()
        }
    }

    /// Cache a peer. Telegram often re-sends the account's own user without
    /// the self flag; the stored identity is kept in that case, and only an
    /// explicit `is_self` changes it.
    pub(crate) fn cache_peer(&mut self, info: &PeerInfo) -> Change {
        let Some(key) = peer_key(info) else {
            log::debug!("Ignored a Telegram peer with an out-of-range id");
            return Change::None;
        };
        let mut info = info.clone();
        let mut change = Change::Deferred;
        if let PeerInfo::User { is_self, .. } = &mut info {
            match *is_self {
                None if self.self_peer == Some(key) => *is_self = Some(true),
                Some(true) if self.self_peer != Some(key) => {
                    if let Some(PeerInfo::User {
                        is_self: previous, ..
                    }) = self.self_peer.and_then(|old| self.peers.get_mut(&old))
                    {
                        *previous = Some(false);
                    }
                    self.self_peer = Some(key);
                    change = Change::Critical;
                }
                Some(false) if self.self_peer == Some(key) => {
                    self.self_peer = None;
                    change = Change::Critical;
                }
                _ => {}
            }
        }
        if change != Change::Critical && self.peers.get(&key) == Some(&info) {
            return Change::None;
        }
        self.peers.insert(key, info);
        change
    }

    pub(crate) fn set_update_state(&mut self, update: UpdateState) -> Change {
        let before = self.updates.clone();
        match update {
            UpdateState::All(state) => self.updates = state,
            UpdateState::Primary { pts, date, seq } => {
                self.updates.pts = pts;
                self.updates.date = date;
                self.updates.seq = seq;
            }
            UpdateState::Secondary { qts } => self.updates.qts = qts,
            UpdateState::Channel { id, pts } => {
                self.updates.channels.retain(|channel| channel.id != id);
                self.updates.channels.push(ChannelState { id, pts });
            }
        }
        if self.updates == before {
            Change::None
        } else {
            Change::Deferred
        }
    }
}
