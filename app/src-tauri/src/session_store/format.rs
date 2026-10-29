//! On-disk envelope of the sealed Telegram session.
//!
//! ```text
//! magic        8 bytes   "TDSESS\0\x01"
//! key source   1 byte    1 = OS keychain, 2 = passphrase (Argon2id)
//! key id      16 bytes   random; names the keychain entry and the key cache slot
//! salt        16 bytes   Argon2id salt (zero for keychain keys)
//! memory KiB   4 bytes   little-endian Argon2id parameters (zero for keychain keys)
//! iterations   4 bytes
//! parallelism  4 bytes
//! nonce       24 bytes   random XChaCha20-Poly1305 nonce, fresh for every write
//! ciphertext   n bytes   sealed session snapshot followed by the 16-byte tag
//! ```
//!
//! Everything before the ciphertext is authenticated as associated data, so a
//! changed key source, key id, salt or KDF parameter fails decryption exactly
//! like a changed ciphertext byte.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::secret::SecretKey;

/// Magic prefix and format version of a sealed session file.
pub(crate) const MAGIC: &[u8; 8] = b"TDSESS\0\x01";
/// First bytes of every SQLite 3 database, as written by earlier releases.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

const KEY_ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// Length of the authenticated header, nonce included.
const HEADER_LEN: usize = MAGIC.len() + 1 + KEY_ID_LEN + SALT_LEN + 12 + NONCE_LEN;

const SOURCE_KEYCHAIN: u8 = 1;
const SOURCE_PASSPHRASE: u8 = 2;

/// Argon2id parameters recorded for a passphrase-protected session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub salt: [u8; SALT_LEN],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Where the session key comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeySource {
    /// A random key held by the operating system's credential store.
    Keychain,
    /// A key derived from a passphrase the user types at startup.
    Passphrase(KdfParams),
}

/// Key metadata of a sealed session; it never contains key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub key_id: [u8; KEY_ID_LEN],
    pub source: KeySource,
}

impl Header {
    /// Hex form of the key id, used as the keychain account name.
    pub(crate) fn key_name(&self) -> String {
        self.key_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn encode(&self, nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (source, params) = match self.source {
            KeySource::Keychain => (SOURCE_KEYCHAIN, None),
            KeySource::Passphrase(params) => (SOURCE_PASSPHRASE, Some(params)),
        };
        let mut at = 0;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(MAGIC);
        put(&[source]);
        put(&self.key_id);
        put(&params.map_or([0; SALT_LEN], |params| params.salt));
        put(&params.map_or(0, |params| params.memory_kib).to_le_bytes());
        put(&params.map_or(0, |params| params.iterations).to_le_bytes());
        put(&params.map_or(0, |params| params.parallelism).to_le_bytes());
        put(nonce);
        out
    }
}

/// What a session file on disk contains.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Contents {
    /// A zero-length placeholder created before the first write.
    Empty,
    /// A plaintext SQLite session written by an earlier release.
    LegacySqlite,
    /// A sealed session with this header.
    Sealed(Header),
    /// Anything else. It is never interpreted.
    Unrecognized,
}

/// Why a sealed session could not be opened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FormatError {
    /// The bytes are not a well-formed sealed session.
    Malformed,
    /// The key is wrong, or the header or ciphertext was modified.
    Authentication,
}

/// Classify session file contents without decrypting them.
pub(crate) fn inspect(bytes: &[u8]) -> Contents {
    if bytes.is_empty() {
        Contents::Empty
    } else if bytes.starts_with(SQLITE_MAGIC) {
        Contents::LegacySqlite
    } else {
        parse_header(bytes).map_or(Contents::Unrecognized, Contents::Sealed)
    }
}

fn parse_header(bytes: &[u8]) -> Result<Header, FormatError> {
    if bytes.len() < HEADER_LEN + TAG_LEN || !bytes.starts_with(MAGIC) {
        return Err(FormatError::Malformed);
    }
    let mut at = MAGIC.len();
    let mut take = |len: usize| {
        let slice = &bytes[at..at + len];
        at += len;
        slice
    };
    let source = take(1)[0];
    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(take(KEY_ID_LEN));
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(take(SALT_LEN));
    let mut word = || {
        let mut value = [0u8; 4];
        value.copy_from_slice(take(4));
        u32::from_le_bytes(value)
    };
    let (memory_kib, iterations, parallelism) = (word(), word(), word());
    let source = match source {
        SOURCE_KEYCHAIN => KeySource::Keychain,
        SOURCE_PASSPHRASE => KeySource::Passphrase(KdfParams {
            salt,
            memory_kib,
            iterations,
            parallelism,
        }),
        _ => return Err(FormatError::Malformed),
    };
    Ok(Header { key_id, source })
}

/// Encrypt a session snapshot under `key` with a fresh random nonce.
pub(crate) fn seal(
    header: &Header,
    key: &SecretKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let aad = header.encode(&nonce);
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| FormatError::Authentication)?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Authenticate and decrypt a sealed session. The returned header is the one
/// that was authenticated, so callers can trust its key source.
pub(crate) fn open(
    bytes: &[u8],
    key: &SecretKey,
) -> Result<(Header, Zeroizing<Vec<u8>>), FormatError> {
    let header = parse_header(bytes)?;
    let (aad, ciphertext) = bytes.split_at(HEADER_LEN);
    let nonce = &aad[HEADER_LEN - NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| FormatError::Authentication)?;
    Ok((header, Zeroizing::new(plaintext)))
}

/// Read the header of a sealed session without authenticating it. Only use
/// it to choose which key to try; trust nothing until [`open`] succeeds.
pub(crate) fn peek_header(bytes: &[u8]) -> Option<Header> {
    parse_header(bytes).ok()
}
