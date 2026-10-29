//! Reader for the plaintext SQLite sessions written by earlier releases.
//!
//! It understands the v1 schema of grammers-session at rev d07f96f and, unlike
//! that crate's own reader, returns an error instead of panicking on rows it
//! does not expect.

use std::net::{SocketAddrV4, SocketAddrV6};
use std::path::Path;

use grammers_session::types::{
    ChannelKind, ChannelState, DcOption, PeerAuth, PeerInfo, UpdatesState,
};

use super::state::{State, MAX_USER_ID};

/// A legacy session that cannot be imported. The text never contains key material.
#[derive(Debug)]
pub(crate) struct LegacyError(pub String);

impl From<sqlite::Error> for LegacyError {
    fn from(error: sqlite::Error) -> Self {
        LegacyError(error.message.unwrap_or_else(|| "SQLite error".into()))
    }
}

const SUBTYPE_SELF: i64 = 1;
const SUBTYPE_BOT: i64 = 2;
const SUBTYPE_MEGAGROUP: i64 = 4;
const SUBTYPE_BROADCAST: i64 = 8;
const SUBTYPE_GIGAGROUP: i64 = 12;
const CHANNEL_OFFSET: i64 = 1_000_000_000_000;

fn int32(value: i64, what: &str) -> Result<i32, LegacyError> {
    i32::try_from(value).map_err(|_| LegacyError(format!("{what} is out of range")))
}

/// Decode one `peer_info` row, or `None` for an id no Telegram peer can have.
fn peer(dialog_id: i64, hash: Option<i64>, subtype: Option<i64>) -> Option<PeerInfo> {
    let auth = hash.map(PeerAuth::from_hash);
    if (1..=MAX_USER_ID).contains(&dialog_id) {
        return Some(PeerInfo::User {
            id: dialog_id,
            auth,
            bot: subtype.map(|value| value & SUBTYPE_BOT != 0),
            is_self: subtype.map(|value| value & SUBTYPE_SELF != 0),
        });
    }
    if (-999_999_999_999..=-1).contains(&dialog_id) {
        return Some(PeerInfo::Chat { id: -dialog_id });
    }
    let id = dialog_id.checked_neg()?.checked_sub(CHANNEL_OFFSET)?;
    let kind = subtype.and_then(|value| {
        if value & SUBTYPE_GIGAGROUP == SUBTYPE_GIGAGROUP {
            Some(ChannelKind::Gigagroup)
        } else if value & SUBTYPE_BROADCAST != 0 {
            Some(ChannelKind::Broadcast)
        } else if value & SUBTYPE_MEGAGROUP != 0 {
            Some(ChannelKind::Megagroup)
        } else {
            None
        }
    });
    let channel = PeerInfo::Channel { id, auth, kind };
    super::state::peer_key(&channel).map(|_| channel)
}

/// Read every table of a legacy session into memory.
///
/// The file is opened read-write so that SQLite rolls back a hot journal
/// left by an interrupted write before anything is read.
pub(crate) fn import(path: &Path) -> Result<State, LegacyError> {
    let connection =
        sqlite::Connection::open_with_flags(path, sqlite::OpenFlags::new().with_read_write())?;
    let mut version = connection.prepare("PRAGMA user_version")?;
    version.next()?;
    let version_number = version.read::<i64, _>(0)?;
    drop(version);
    let mut state = State::default();
    match version_number {
        // A file created but never initialized holds no account yet.
        0 => return Ok(state),
        1 => {}
        other => {
            return Err(LegacyError(format!(
                "unsupported session schema version {other}"
            )))
        }
    }

    let mut home = connection.prepare("SELECT dc_id FROM dc_home LIMIT 1")?;
    if home.next()? == sqlite::State::Row {
        state.home_dc = int32(home.read::<i64, _>(0)?, "home DC")?;
    }
    drop(home);

    let mut options = connection.prepare("SELECT dc_id, ipv4, ipv6, auth_key FROM dc_option")?;
    while options.next()? == sqlite::State::Row {
        let id = int32(options.read::<i64, _>(0)?, "DC id")?;
        let ipv4: SocketAddrV4 = options
            .read::<String, _>(1)?
            .parse()
            .map_err(|_| LegacyError("invalid DC IPv4 address".into()))?;
        let ipv6: SocketAddrV6 = options
            .read::<String, _>(2)?
            .parse()
            .map_err(|_| LegacyError("invalid DC IPv6 address".into()))?;
        let auth_key = match options.read::<Option<Vec<u8>>, _>(3)? {
            None => None,
            Some(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                Some(
                    <[u8; 256]>::try_from(bytes.as_slice())
                        .map_err(|_| LegacyError("invalid DC authorization key length".into()))?,
                )
            }
        };
        state.dc_options.insert(
            id,
            DcOption {
                id,
                ipv4,
                ipv6,
                auth_key,
            },
        );
    }
    drop(options);

    let mut peers = connection.prepare("SELECT peer_id, hash, subtype FROM peer_info")?;
    let mut skipped = 0usize;
    while peers.next()? == sqlite::State::Row {
        let decoded = peer(
            peers.read::<i64, _>(0)?,
            peers.read::<Option<i64>, _>(1)?,
            peers.read::<Option<i64>, _>(2)?,
        );
        match decoded {
            Some(info) => state.insert_imported(info)?,
            None => skipped += 1,
        }
    }
    drop(peers);
    if skipped > 0 {
        log::warn!(
            "Skipped {skipped} cached Telegram peers with invalid ids during session migration"
        );
    }

    let mut updates = connection.prepare("SELECT pts, qts, date, seq FROM update_state LIMIT 1")?;
    if updates.next()? == sqlite::State::Row {
        state.updates = UpdatesState {
            pts: int32(updates.read::<i64, _>(0)?, "pts")?,
            qts: int32(updates.read::<i64, _>(1)?, "qts")?,
            date: int32(updates.read::<i64, _>(2)?, "date")?,
            seq: int32(updates.read::<i64, _>(3)?, "seq")?,
            channels: Vec::new(),
        };
    }
    drop(updates);

    let mut channels = connection.prepare("SELECT peer_id, pts FROM channel_state")?;
    while channels.next()? == sqlite::State::Row {
        state.updates.channels.push(ChannelState {
            id: channels.read::<i64, _>(0)?,
            pts: int32(channels.read::<i64, _>(1)?, "channel pts")?,
        });
    }
    Ok(state)
}

/// Read the account id from a legacy session without importing it.
///
/// Only identity metadata of the pinned grammers v1 schema is read: the
/// self-user subtype is 1 (or 3 for a bot) and user ids are positive Bot API
/// ids. A future layout, an invalid id or several self rows is an error
/// rather than a guess about the owner. No authorization key is read.
pub(crate) fn read_owner(path: &Path) -> Result<Option<i64>, LegacyError> {
    let unsupported = || LegacyError("unsupported session identity layout".into());
    let mut connection =
        sqlite::Connection::open_with_flags(path, sqlite::OpenFlags::new().with_read_only())?;
    connection.set_busy_timeout(250)?;
    connection.execute("BEGIN")?;
    let mut version = connection.prepare("PRAGMA user_version")?;
    if version.next()? != sqlite::State::Row || version.read::<i64, _>(0)? != 1 {
        return Err(unsupported());
    }
    drop(version);
    let mut peer = connection
        .prepare("SELECT peer_id, subtype FROM peer_info WHERE subtype & 1 != 0 LIMIT 2")?;
    if peer.next()? != sqlite::State::Row {
        return Ok(None);
    }
    let owner = peer.read::<i64, _>(0)?;
    let subtype = peer.read::<i64, _>(1)?;
    if !(1..=MAX_USER_ID).contains(&owner)
        || !matches!(subtype, 1 | 3)
        || peer.next()? != sqlite::State::Done
    {
        return Err(unsupported());
    }
    Ok(Some(owner))
}
