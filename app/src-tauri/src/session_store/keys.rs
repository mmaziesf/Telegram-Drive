//! Where session keys come from.
//!
//! The preferred source is a random 256-bit key held by the operating system's
//! credential store: Secret Service on Linux, Keychain on macOS and Credential
//! Manager on Windows. When no credential store is reachable the key is
//! derived from a passphrase with Argon2id instead; the passphrase is kept in
//! memory only, for the life of the process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use base64::Engine as _;
use zeroize::Zeroizing;

use super::format::{Header, KdfParams, KeySource};
use crate::crypto::kdf::derive_passphrase_key;
use crate::crypto::policy::{
    ARGON2_ITERATIONS_FLOOR, ARGON2_MEMORY_FLOOR_KIB, ARGON2_PARALLELISM_FLOOR,
};
use crate::crypto::random::{random_key, random_salt, random_uuid};
use crate::crypto::secret::SecretKey;

/// Shortest passphrase accepted for a new passphrase-protected session.
pub(crate) const MIN_PASSPHRASE_CHARS: usize = 12;

/// The credential store could not be used. The message never contains a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyStoreUnavailable(pub String);

/// A store for session keys, addressed by the hex key id from the session header.
pub(crate) trait KeyStore: Send + Sync {
    /// Save a key under `name`, replacing any previous value.
    fn store(&self, name: &str, key: &SecretKey) -> Result<(), KeyStoreUnavailable>;
    /// Load the key saved under `name`, or `None` if there is none.
    fn load(&self, name: &str) -> Result<Option<SecretKey>, KeyStoreUnavailable>;
    /// Remove the key saved under `name`. Removing a missing key succeeds.
    fn delete(&self, name: &str) -> Result<(), KeyStoreUnavailable>;
}

fn encode_key(key: &SecretKey) -> Zeroizing<String> {
    Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.expose()))
}

fn decode_key(value: &str) -> Option<SecretKey> {
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .ok()?,
    );
    let key: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(SecretKey::new(key))
}

/// The operating system's credential store, through the `keyring` crate.
pub(crate) struct OsKeychain;

impl OsKeychain {
    const SERVICE: &'static str = "io.github.mmaziesf.unofficialtelegramdrive.telegram-session";

    fn entry(name: &str) -> Result<keyring::Entry, KeyStoreUnavailable> {
        keyring::Entry::new(Self::SERVICE, name).map_err(unavailable)
    }
}

fn unavailable(error: keyring::Error) -> KeyStoreUnavailable {
    KeyStoreUnavailable(error.to_string())
}

impl KeyStore for OsKeychain {
    fn store(&self, name: &str, key: &SecretKey) -> Result<(), KeyStoreUnavailable> {
        Self::entry(name)?
            .set_password(&encode_key(key))
            .map_err(unavailable)
    }

    fn load(&self, name: &str) -> Result<Option<SecretKey>, KeyStoreUnavailable> {
        match Self::entry(name)?.get_password() {
            Ok(value) => Ok(decode_key(&Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }

    fn delete(&self, name: &str) -> Result<(), KeyStoreUnavailable> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(unavailable(error)),
        }
    }
}

/// A key store that keeps one file per key in a directory. Only test builds
/// use it, so native end-to-end runs work on CI machines without a desktop
/// credential store and keep their keys across driver restarts.
#[cfg(any(test, feature = "native-e2e"))]
pub(crate) struct DirectoryKeyStore(pub std::path::PathBuf);

#[cfg(any(test, feature = "native-e2e"))]
impl KeyStore for DirectoryKeyStore {
    fn store(&self, name: &str, key: &SecretKey) -> Result<(), KeyStoreUnavailable> {
        let fail = |error: std::io::Error| KeyStoreUnavailable(error.to_string());
        std::fs::create_dir_all(&self.0).map_err(fail)?;
        std::fs::write(self.0.join(name), encode_key(key).as_bytes()).map_err(fail)
    }

    fn load(&self, name: &str) -> Result<Option<SecretKey>, KeyStoreUnavailable> {
        match std::fs::read_to_string(self.0.join(name)) {
            Ok(value) => Ok(decode_key(&Zeroizing::new(value))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(KeyStoreUnavailable(error.to_string())),
        }
    }

    fn delete(&self, name: &str) -> Result<(), KeyStoreUnavailable> {
        match std::fs::remove_file(self.0.join(name)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KeyStoreUnavailable(error.to_string())),
        }
    }
}

/// A credential store that is never reachable, for tests of the passphrase path.
#[cfg(test)]
pub(crate) struct NoKeyStore;

#[cfg(test)]
impl KeyStore for NoKeyStore {
    fn store(&self, _: &str, _: &SecretKey) -> Result<(), KeyStoreUnavailable> {
        Err(KeyStoreUnavailable(
            "no credential store in this test".into(),
        ))
    }
    fn load(&self, _: &str) -> Result<Option<SecretKey>, KeyStoreUnavailable> {
        Err(KeyStoreUnavailable(
            "no credential store in this test".into(),
        ))
    }
    fn delete(&self, _: &str) -> Result<(), KeyStoreUnavailable> {
        Err(KeyStoreUnavailable(
            "no credential store in this test".into(),
        ))
    }
}

static INSTALLED_STORE: OnceLock<Arc<dyn KeyStore>> = OnceLock::new();

/// The key store the application uses: the OS credential store unless a
/// native end-to-end run installed a directory-backed one first.
pub(crate) fn key_store() -> Arc<dyn KeyStore> {
    INSTALLED_STORE.get_or_init(|| Arc::new(OsKeychain)).clone()
}

/// Replace the OS credential store for a native end-to-end run.
#[cfg(feature = "native-e2e")]
pub(crate) fn install_key_store(store: Arc<dyn KeyStore>) {
    if INSTALLED_STORE.set(store).is_err() {
        log::warn!("The session key store was already selected for this process");
    }
}

/// Derive the key of a passphrase-protected session with Argon2id.
pub(crate) fn derive(passphrase: &str, params: &KdfParams) -> Result<SecretKey, KeyError> {
    derive_passphrase_key(
        passphrase.as_bytes(),
        &params.salt,
        params.memory_kib,
        params.iterations,
        params.parallelism,
    )
    .map_err(|_| KeyError::Derivation)
}

/// Keys and passphrase held in memory for the life of the process.
#[derive(Default)]
pub(crate) struct KeyCache {
    keys: Mutex<HashMap<String, SecretKey>>,
    passphrase: Mutex<Option<Zeroizing<String>>>,
}

/// Why no key could be produced for a session.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// A passphrase is needed and none has been entered in this process.
    PassphraseRequired,
    /// The credential store holding this session's key cannot be reached.
    KeychainUnavailable(String),
    /// The credential store is reachable but no longer holds this session's key.
    KeyMissing,
    /// Argon2id rejected the recorded parameters.
    Derivation,
}

impl KeyCache {
    /// The process-wide cache.
    pub(crate) fn global() -> &'static KeyCache {
        static CACHE: OnceLock<KeyCache> = OnceLock::new();
        CACHE.get_or_init(KeyCache::default)
    }

    /// Remember the passphrase used for passphrase-protected sessions.
    pub(crate) fn set_passphrase(&self, passphrase: Zeroizing<String>) {
        *self
            .passphrase
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(passphrase);
    }

    /// Forget the passphrase, for example after it failed to open a session.
    pub(crate) fn clear_passphrase(&self) {
        *self
            .passphrase
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether a passphrase has been entered in this process.
    pub(crate) fn has_passphrase(&self) -> bool {
        self.passphrase
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Forget a cached key, for example after it failed to decrypt.
    pub(crate) fn forget(&self, header: &Header) {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&header.key_name());
    }

    fn cached(&self, header: &Header) -> Option<SecretKey> {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&header.key_name())
            .cloned()
    }

    /// Keep a key that was just verified against a session.
    pub(crate) fn remember(&self, header: &Header, key: &SecretKey) {
        self.keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(header.key_name(), key.clone());
    }

    fn derive(&self, params: &KdfParams) -> Result<SecretKey, KeyError> {
        let passphrase = self
            .passphrase
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(KeyError::PassphraseRequired)?;
        derive(&passphrase, params)
    }

    /// The key for an existing session, from memory, the credential store or
    /// the passphrase, as its header says.
    pub(crate) fn key_for(
        &self,
        header: &Header,
        store: Option<&dyn KeyStore>,
    ) -> Result<SecretKey, KeyError> {
        if let Some(key) = self.cached(header) {
            return Ok(key);
        }
        let key = match header.source {
            KeySource::Keychain => {
                let store = store.ok_or_else(|| {
                    KeyError::KeychainUnavailable("no credential store on this platform".into())
                })?;
                store
                    .load(&header.key_name())
                    .map_err(|error| KeyError::KeychainUnavailable(error.0))?
                    .ok_or(KeyError::KeyMissing)?
            }
            KeySource::Passphrase(params) => self.derive(&params)?,
        };
        self.remember(header, &key);
        Ok(key)
    }

    /// Create the key for a new session: a random key in the credential store
    /// when one is reachable, otherwise a key derived from the passphrase.
    pub(crate) fn new_key(
        &self,
        store: Option<&dyn KeyStore>,
    ) -> Result<(Header, SecretKey), KeyError> {
        let key_id = random_uuid();
        if let Some(store) = store {
            let header = Header {
                key_id,
                source: KeySource::Keychain,
            };
            let key = SecretKey::new(random_key());
            // Read the key back: some stores accept a write they cannot persist.
            let stored = store
                .store(&header.key_name(), &key)
                .and_then(|()| store.load(&header.key_name()));
            match stored {
                Ok(Some(read)) if read.expose() == key.expose() => {
                    self.remember(&header, &key);
                    return Ok((header, key));
                }
                Ok(_) => {
                    log::warn!("The credential store did not keep the session key; using the passphrase instead");
                    let _ = store.delete(&header.key_name());
                }
                Err(error) => {
                    log::warn!("No credential store is available for the session key ({}); using the passphrase instead", error.0);
                }
            }
        }
        let params = KdfParams {
            salt: random_salt(),
            memory_kib: ARGON2_MEMORY_FLOOR_KIB,
            iterations: ARGON2_ITERATIONS_FLOOR,
            parallelism: ARGON2_PARALLELISM_FLOOR,
        };
        let header = Header {
            key_id,
            source: KeySource::Passphrase(params),
        };
        let key = self.derive(&params)?;
        self.remember(&header, &key);
        Ok((header, key))
    }
}

/// Whether the credential store answers at all. A missing probe entry is a
/// healthy answer; an error means it cannot be reached.
pub(crate) fn keychain_reachable(store: Option<&dyn KeyStore>) -> bool {
    store.is_some_and(|store| store.load("availability-probe").is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_keys_are_random_cached_and_reloaded() {
        let directory = super::super::tests::TestDir::new();
        let store = DirectoryKeyStore(directory.path().join("keys"));
        let cache = KeyCache::default();
        let (header, key) = cache.new_key(Some(&store)).expect("new key");
        assert_eq!(header.source, KeySource::Keychain);
        let (_, other) = cache.new_key(Some(&store)).expect("second key");
        assert_ne!(key.expose(), other.expose());

        let fresh = KeyCache::default();
        assert_eq!(
            fresh
                .key_for(&header, Some(&store))
                .expect("reload")
                .expose(),
            key.expose()
        );
        store.delete(&header.key_name()).expect("delete");
        assert_eq!(
            cache
                .key_for(&header, Some(&store))
                .expect("cached")
                .expose(),
            key.expose()
        );
        assert_eq!(
            KeyCache::default().key_for(&header, Some(&store)).err(),
            Some(KeyError::KeyMissing)
        );
    }

    #[test]
    fn without_a_keychain_the_passphrase_is_required() {
        let cache = KeyCache::default();
        assert_eq!(
            cache.new_key(Some(&NoKeyStore)).err(),
            Some(KeyError::PassphraseRequired)
        );
        cache.set_passphrase(Zeroizing::new("correct horse battery".into()));
        let (header, key) = cache.new_key(Some(&NoKeyStore)).expect("passphrase key");
        assert!(matches!(header.source, KeySource::Passphrase(_)));

        // The same passphrase derives the same key in a later process.
        let later = KeyCache::default();
        assert_eq!(
            later.key_for(&header, None).err(),
            Some(KeyError::PassphraseRequired)
        );
        later.set_passphrase(Zeroizing::new("correct horse battery".into()));
        assert_eq!(
            later.key_for(&header, None).expect("derive").expose(),
            key.expose()
        );

        let wrong = KeyCache::default();
        wrong.set_passphrase(Zeroizing::new("another passphrase".into()));
        assert_ne!(
            wrong.key_for(&header, None).expect("derive").expose(),
            key.expose()
        );
    }

    #[test]
    fn unreachable_keychain_is_reported_for_keychain_sessions() {
        let header = Header {
            key_id: [1; 16],
            source: KeySource::Keychain,
        };
        assert!(matches!(
            KeyCache::default().key_for(&header, Some(&NoKeyStore)),
            Err(KeyError::KeychainUnavailable(_))
        ));
        assert!(!keychain_reachable(Some(&NoKeyStore)));
        assert!(!keychain_reachable(None));
    }
}
