//! Known-answer vectors for the TDENC2 envelope.
//!
//! The expected bytes come from `scripts/generate-tdenc2-kat.py`, an
//! independent Python encoder written from the format description. It shares
//! no code with the Rust implementation and uses Python's `cryptography`
//! package for ChaCha20-Poly1305 and HKDF, plus its own HChaCha20 checked
//! against draft-irtf-cfrg-xchacha-03 section 2.2.1. The vectors pin the
//! header layout and authenticator, the encrypted metadata, chunk nonce
//! derivation (prefix plus little-endian record index), the chunk and final
//! record AAD, and the final record. Any change to the format fails here.
//!
//! The same file also checks the HKDF-SHA-256 helper against RFC 5869, and
//! that a decrypting reader refuses a body whose length differs from the size
//! the header declares.

use app_lib::crypto::envelope::decrypt_reader::DecryptReader;
use app_lib::crypto::envelope::encrypt_reader::{EncryptingReader, EncryptionSession};
use app_lib::crypto::envelope::KeySlotEntry;
use app_lib::crypto::error::{CryptoError, CryptoErrorCode, CryptoResult};
use app_lib::crypto::kdf::derive_domain_key;
use app_lib::crypto::policy::{self, KdfAlgorithm, SlotKind};
use app_lib::crypto::secret::SecretKey;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

const EMPTY_ENVELOPE: &[&str] = &[
    "5444454e43320200404142434445464748494a4b4c4d4e4f0100ca0000000000100068000000000000000000",
    "000000000000808182838485868788898a8b8c8d8e8f4d08978b9ce7d687a09c066f221365df335f6be8be67",
    "253f2bd6078baaee314f01000200000000000000000000000000111111111111111111111111111111112222",
    "2222222222222222222222222222222222222222222233333333333333333333333333333333333333333333",
    "3333333333333333333333333333333333333333333333333333c0b16b303ed93e697caa6eec6aea5d93a8fe",
    "63ae5fe977f7a1cbefdf357285b9634d57f52512b71dde6e3f21bf8c7c2a6edd4f61716809a3bcbe72b3bb92",
    "039028c142f4",
];

const SMALL_ENVELOPE: &[&str] = &[
    "5444454e43320200404142434445464748494a4b4c4d4e4f0100ec0000000000100068000000220000006400",
    "000000000000808182838485868788898a8b8c8d8e8f4786ede8569452c322cdf1e2d6e8a57dced0ed3197e6",
    "c1867cde9df550362e4201000200000000000000000000000000111111111111111111111111111111112222",
    "2222222222222222222222222222222222222222222233333333333333333333333333333333333333333333",
    "333333333333333333333333333333333333333333333333333339c2e89f6cf503d1eefe126c04d6555762c2",
    "897166c26efd106e6be400e76e6cab5400a92e02c0a09f9b47b1f47c461d323222c2a88e567948cfa8718b40",
    "d758790162f717f4f4f477824f3b250dc0ef6adcc34f50dba54ead4c393b49b092a54e816e511f353c2d0ecd",
    "f927f81ed6dcd555aac8be55a2da0eecd77c0937f09a47da6ee51b623f322edcf29902949fa8c2ee0537ef19",
    "c1b16b305ad93e697caa6eec24797e89bea96f6d8dea70b30a6f05512d1f2c48e27786606aa56061d983365e",
    "bf8c7c2a6edd4f61ac26854b5213f615a955ced45492089a",
];

const TWO_CHUNK_SHA256: &str = "877e1131720ec620d7978d4b166c707ceb849128ff16ae83cf1abafafe972067";
const TWO_CHUNK_LENGTH: usize = 1048915;

const TWO_CHUNK_FINAL_RECORD: &[&str] = &[
    "c2b16b301bd92e697caa6eeca75065749131bb05e2b85237dd1bf53222cd0ce7a6d768cdd1e5aa34454cbe76",
    "bf8c7c2a6edd4f6120c5d6d8a1527c2ccd15b08c78906342",
];

const SMALL_METADATA: &[u8] = br#"{"name":"kat.txt"}"#;

fn dek() -> [u8; 32] {
    std::array::from_fn(|index| index as u8)
}

fn file_uuid() -> [u8; 16] {
    std::array::from_fn(|index| 0x40 + index as u8)
}

fn nonce_prefix() -> [u8; 16] {
    std::array::from_fn(|index| 0x80 + index as u8)
}

/// A vault key slot with fixed, opaque contents. Decryption is given the DEK
/// directly, so the wrapped DEK is never unwrapped.
fn fixed_slot() -> KeySlotEntry {
    KeySlotEntry {
        kind: SlotKind::Vault as u8,
        slot_id: 0,
        kdf_algorithm: KdfAlgorithm::HkdfSha256 as u16,
        argon2_memory_kib: 0,
        argon2_iterations: 0,
        argon2_parallelism: 0,
        salt: [0x11; 16],
        wrap_nonce: [0x22; 24],
        wrapped_dek: [0x33; 48],
    }
}

/// Deterministic, non-repeating test content of `length` bytes.
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 31 % 251) as u8).collect()
}

fn unhex(parts: &[&str]) -> Vec<u8> {
    let text: String = parts.concat();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn io_error(error: std::io::Error) -> CryptoError {
    CryptoError::new(CryptoErrorCode::IoError, error.to_string())
}

/// Encrypt with the fixed keys through the streaming reader uploads use.
/// Returns the envelope and its header length.
fn seal(plaintext: &[u8], metadata: &[u8]) -> CryptoResult<(Vec<u8>, usize)> {
    let session = EncryptionSession::new_with_keys(
        plaintext.len() as u64,
        vec![fixed_slot()],
        metadata.to_vec(),
        SecretKey::new(dek()),
        file_uuid(),
        nonce_prefix(),
    )?;
    let header_length = session.header_bytes.len();
    let mut reader = EncryptingReader::new(plaintext, session);
    let mut bytes = Vec::new();
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(io_error)?
        .block_on(reader.read_to_end(&mut bytes))
        .map_err(io_error)?;
    Ok((bytes, header_length))
}

/// Decrypt a whole envelope; returns the plaintext and metadata.
fn open(bytes: &[u8], header_length: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let header = bytes
        .get(..header_length)
        .ok_or_else(CryptoError::truncated)?;
    let mut reader = DecryptReader::new(header, SecretKey::new(dek()))?;
    let plaintext = reader.feed(&bytes[header_length..])?;
    reader.finish()?;
    Ok((plaintext, reader.metadata_plaintext().to_vec()))
}

fn header_length_of(envelope: &[u8]) -> usize {
    u32::from_le_bytes([envelope[26], envelope[27], envelope[28], envelope[29]]) as usize
}

#[test]
fn reference_encoder_vectors_match_byte_for_byte() -> CryptoResult<()> {
    let expected = unhex(EMPTY_ENVELOPE);
    let (empty, header_length) = seal(&[], &[])?;
    assert_eq!(hex(&empty), hex(&expected));
    assert_eq!(header_length, header_length_of(&expected));

    let expected = unhex(SMALL_ENVELOPE);
    let (small, header_length) = seal(&pattern(100), SMALL_METADATA)?;
    assert_eq!(hex(&small), hex(&expected));
    assert_eq!(header_length, header_length_of(&expected));

    let chunk = policy::DEFAULT_CHUNK_SIZE as usize;
    let (two_chunks, _) = seal(&pattern(chunk + 37), &[])?;
    assert_eq!(two_chunks.len(), TWO_CHUNK_LENGTH);
    assert_eq!(hex(&Sha256::digest(&two_chunks)), TWO_CHUNK_SHA256);
    let final_record = unhex(TWO_CHUNK_FINAL_RECORD);
    assert_eq!(
        hex(&two_chunks[two_chunks.len() - final_record.len()..]),
        hex(&final_record)
    );
    Ok(())
}

#[test]
fn reference_encoder_vectors_decrypt_to_their_inputs() -> CryptoResult<()> {
    let empty = unhex(EMPTY_ENVELOPE);
    assert_eq!(
        open(&empty, header_length_of(&empty))?,
        (Vec::new(), Vec::new())
    );

    let small = unhex(SMALL_ENVELOPE);
    assert_eq!(
        open(&small, header_length_of(&small))?,
        (pattern(100), SMALL_METADATA.to_vec())
    );
    Ok(())
}

#[test]
fn hkdf_sha256_matches_rfc_5869_test_case_3() -> CryptoResult<()> {
    // RFC 5869 A.3: IKM = 22 bytes of 0x0b, empty salt and info, L = 42.
    let okm = derive_domain_key(&[0x0b; 22], &[], 42)?;
    assert_eq!(
        hex(&okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
    Ok(())
}

fn assert_rejected(result: CryptoResult<(Vec<u8>, Vec<u8>)>, case: &str) {
    let code = result.err().map(|error| error.code);
    assert!(
        matches!(
            code,
            Some(
                CryptoErrorCode::AuthFailed
                    | CryptoErrorCode::WrongKeyOrCorrupt
                    | CryptoErrorCode::HeaderInvalid
                    | CryptoErrorCode::PolicyRejected
                    | CryptoErrorCode::Truncated
                    | CryptoErrorCode::SizeOverflow
            )
        ),
        "{case}: expected a rejection, got {code:?}"
    );
}

#[test]
fn a_body_that_differs_from_the_declared_size_is_rejected() -> CryptoResult<()> {
    let (declared_100, header_length) = seal(&pattern(100), &[])?;
    for actual in [0usize, 99, 101, 4096] {
        // Same keys, file identity and nonce prefix; only the length differs.
        let (other, other_header_length) = seal(&pattern(actual), &[])?;
        let mut spliced = declared_100[..header_length].to_vec();
        spliced.extend_from_slice(&other[other_header_length..]);
        assert_rejected(
            open(&spliced, header_length),
            &format!("header declares 100 bytes, body holds {actual}"),
        );
    }
    Ok(())
}

#[test]
fn an_edited_declared_size_is_rejected() -> CryptoResult<()> {
    let (sealed, header_length) = seal(&pattern(100), &[])?;
    // The declared plaintext length is the little-endian u64 at offset 42.
    for declared in [0u64, 99, 101, 1 << 31, u64::MAX] {
        let mut edited = sealed.clone();
        edited[42..50].copy_from_slice(&declared.to_le_bytes());
        assert_rejected(
            open(&edited, header_length),
            &format!("declared size edited to {declared}"),
        );
    }
    Ok(())
}
