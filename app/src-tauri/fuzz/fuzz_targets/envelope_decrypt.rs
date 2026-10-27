//! Feeds attacker-controlled ciphertext to the streaming decrypter behind a
//! valid header (built once with fixed keys), split into fragments chosen by
//! the input, and also tries random-access chunk decryption. Decryption must
//! fail cleanly; it must never panic or return plaintext for forged records.
#![no_main]

use std::sync::OnceLock;

use app_lib::crypto::envelope::decrypt_reader::DecryptReader;
use app_lib::crypto::envelope::encrypt_reader::EncryptionSession;
use app_lib::crypto::envelope::{wrap_dek, KeySlotContext, KeySlotEntry};
use app_lib::crypto::error::CryptoResult;
use app_lib::crypto::kdf::derive_file_wrapping_key;
use app_lib::crypto::policy::{self, KdfAlgorithm, SlotKind};
use app_lib::crypto::secret::SecretKey;
use libfuzzer_sys::fuzz_target;

const DEK: [u8; 32] = [9; 32];
const FILE_UUID: [u8; 16] = [1; 16];

fn slot() -> CryptoResult<KeySlotEntry> {
    let salt = [3; 16];
    let kind = SlotKind::Vault as u8;
    let kdf = KdfAlgorithm::HkdfSha256 as u16;
    let wrapping = derive_file_wrapping_key(&SecretKey::new([5; 32]), &FILE_UUID, &salt, kind, 0)?;
    let context = KeySlotContext {
        file_uuid: &FILE_UUID,
        format_version: policy::FORMAT_VERSION,
    };
    let dek = SecretKey::new(DEK);
    let (wrapped_dek, wrap_nonce) =
        wrap_dek(&context, &dek, &wrapping, kind, 0, kdf, 0, 0, 0, &salt)?;
    Ok(KeySlotEntry {
        kind,
        slot_id: 0,
        kdf_algorithm: kdf,
        argon2_memory_kib: 0,
        argon2_iterations: 0,
        argon2_parallelism: 0,
        salt,
        wrap_nonce,
        wrapped_dek,
    })
}

fn session() -> CryptoResult<EncryptionSession> {
    // One short record keeps runs fast; a multi-record body at the default
    // chunk size would need megabytes of input per case.
    EncryptionSession::new_with_keys(
        64,
        vec![slot()?],
        b"fuzz".to_vec(),
        SecretKey::new(DEK),
        FILE_UUID,
        [2; 16],
    )
}

fn header() -> &'static [u8] {
    static HEADER: OnceLock<Vec<u8>> = OnceLock::new();
    HEADER.get_or_init(|| match session() {
        Ok(session) => session.header_bytes,
        Err(error) => {
            eprintln!("could not build the fuzz header: {error:?}");
            std::process::abort()
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&split, body)) = data.split_first() else {
        return;
    };
    let Ok(mut reader) = DecryptReader::new(header(), SecretKey::new(DEK)) else {
        std::process::abort()
    };
    let fragment = usize::from(split).max(1);
    let mut plaintext = Vec::new();
    for piece in body.chunks(fragment) {
        match reader.feed(piece) {
            Ok(bytes) => plaintext.extend_from_slice(&bytes),
            Err(_) => break,
        }
    }
    // Forged records must never authenticate.
    if reader.finish().is_ok() || !plaintext.is_empty() {
        std::process::abort()
    }
    if let Ok(chunk) = DecryptReader::new(header(), SecretKey::new(DEK)) {
        let _ = chunk.decrypt_chunk_at(u32::from(split), body);
    }
});
