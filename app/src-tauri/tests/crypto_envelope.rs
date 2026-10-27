//! Adversarial and property tests for the TDENC2 file envelope, DEK key slots
//! and vault recovery bundles.
//!
//! Every case drives only the public `app_lib::crypto` API with in-memory
//! buffers, so the suite is fast, deterministic in its assertions and needs no
//! application fixtures. It checks the guarantees uploads rely on: encryption
//! round-trips, any modification is rejected, the wrong key never yields
//! plaintext, and nonces are never reused across files or key slots.

use std::collections::HashSet;

use app_lib::crypto::envelope::decrypt_reader::DecryptReader;
use app_lib::crypto::envelope::encrypt_reader::{EncryptingReader, EncryptionSession};
use app_lib::crypto::envelope::{unwrap_dek, wrap_dek, KeySlotContext, KeySlotEntry};
use app_lib::crypto::error::{CryptoError, CryptoErrorCode, CryptoResult};
use app_lib::crypto::kdf::derive_file_wrapping_key;
use app_lib::crypto::policy::{self, KdfAlgorithm, SlotKind};
use app_lib::crypto::random;
use app_lib::crypto::secret::SecretKey;
use app_lib::crypto::vault::export::{create_recovery_bundle, import_recovery_bundle};
use proptest::prelude::*;
use tokio::io::AsyncReadExt;

/// A complete envelope plus the length of its authenticated header.
struct Sealed {
    bytes: Vec<u8>,
    header_length: usize,
}

impl Sealed {
    fn header(&self) -> &[u8] {
        &self.bytes[..self.header_length]
    }

    fn body(&self) -> &[u8] {
        &self.bytes[self.header_length..]
    }
}

/// Inputs that fully determine an envelope, so tests can reproduce one.
struct SealInput<'a> {
    plaintext: &'a [u8],
    metadata: &'a [u8],
    dek: [u8; 32],
    vault_master: [u8; 32],
    file_uuid: [u8; 16],
    nonce_prefix: [u8; 16],
}

impl<'a> SealInput<'a> {
    /// Fresh random identifiers, as production uploads use.
    fn fresh(plaintext: &'a [u8], metadata: &'a [u8], dek: [u8; 32]) -> Self {
        Self {
            plaintext,
            metadata,
            dek,
            vault_master: random::random_key(),
            file_uuid: random::random_uuid(),
            nonce_prefix: random::random_nonce_prefix(),
        }
    }
}

fn vault_slot(
    vault_master: &SecretKey,
    file_uuid: &[u8; 16],
    dek: &SecretKey,
) -> CryptoResult<KeySlotEntry> {
    let salt = random::random_salt();
    let kind = SlotKind::Vault as u8;
    let kdf = KdfAlgorithm::HkdfSha256 as u16;
    let wrapping = derive_file_wrapping_key(vault_master, file_uuid, &salt, kind, 0)?;
    let context = KeySlotContext {
        file_uuid,
        format_version: policy::FORMAT_VERSION,
    };
    let (wrapped_dek, wrap_nonce) =
        wrap_dek(&context, dek, &wrapping, kind, 0, kdf, 0, 0, 0, &salt)?;
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

fn runtime() -> CryptoResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|error| CryptoError::new(CryptoErrorCode::IoError, error.to_string()))
}

/// Encrypt through the streaming reader used by uploads.
fn seal(input: &SealInput<'_>) -> CryptoResult<Sealed> {
    let dek = SecretKey::new(input.dek);
    let slot = vault_slot(&SecretKey::new(input.vault_master), &input.file_uuid, &dek)?;
    let session = EncryptionSession::new_with_keys(
        input.plaintext.len() as u64,
        vec![slot],
        input.metadata.to_vec(),
        dek,
        input.file_uuid,
        input.nonce_prefix,
    )?;
    stream(input.plaintext, session)
}

fn stream(plaintext: &[u8], session: EncryptionSession) -> CryptoResult<Sealed> {
    let header_length = session.header_bytes.len();
    let expected_length = session.total_ciphertext_length;
    let mut reader = EncryptingReader::new(plaintext, session);
    let mut bytes = Vec::new();
    runtime()?
        .block_on(reader.read_to_end(&mut bytes))
        .map_err(|error| CryptoError::new(CryptoErrorCode::IoError, error.to_string()))?;
    if bytes.len() as u64 != expected_length {
        return Err(CryptoError::internal(
            "Envelope length differs from its prediction",
        ));
    }
    Ok(Sealed {
        bytes,
        header_length,
    })
}

/// Decrypted plaintext and header metadata.
struct Opened {
    plaintext: Vec<u8>,
    metadata: Vec<u8>,
}

/// Decrypt a whole envelope, feeding the body in `fragment`-sized pieces the
/// way network downloads arrive.
fn open(
    bytes: &[u8],
    header_length: usize,
    dek: [u8; 32],
    fragment: usize,
) -> CryptoResult<Opened> {
    let header = bytes
        .get(..header_length)
        .ok_or_else(CryptoError::truncated)?;
    let mut reader = DecryptReader::new(header, SecretKey::new(dek))?;
    let mut plaintext = Vec::new();
    for piece in bytes[header_length..].chunks(fragment.max(1)) {
        plaintext.extend(reader.feed(piece)?);
    }
    reader.finish()?;
    Ok(Opened {
        plaintext,
        metadata: reader.metadata_plaintext().to_vec(),
    })
}

fn open_sealed(sealed: &Sealed, dek: [u8; 32]) -> CryptoResult<Opened> {
    open(&sealed.bytes, sealed.header_length, dek, usize::MAX)
}

fn is_rejection(code: &CryptoErrorCode) -> bool {
    matches!(
        code,
        CryptoErrorCode::AuthFailed
            | CryptoErrorCode::WrongKeyOrCorrupt
            | CryptoErrorCode::HeaderInvalid
            | CryptoErrorCode::UnsupportedVersion
            | CryptoErrorCode::PolicyRejected
            | CryptoErrorCode::Truncated
            | CryptoErrorCode::SizeOverflow
    )
}

fn fail(error: CryptoError) -> TestCaseError {
    TestCaseError::fail(format!("{:?}: {}", error.code, error))
}

/// Deterministic, non-repeating test content of `length` bytes.
fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 31 % 251) as u8).collect()
}

proptest! {
    // Failures print a minimal counterexample; regression files are not
    // written into the repository.
    #![proptest_config(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn any_plaintext_and_metadata_round_trip_in_any_fragmentation(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        metadata in prop::collection::vec(any::<u8>(), 0..512),
        fragment in 1usize..600,
        dek in any::<[u8; 32]>(),
    ) {
        let sealed = seal(&SealInput::fresh(&plaintext, &metadata, dek)).map_err(fail)?;
        let opened = open(&sealed.bytes, sealed.header_length, dek, fragment).map_err(fail)?;
        prop_assert_eq!(opened.plaintext, plaintext);
        prop_assert_eq!(opened.metadata, metadata);
    }

    #[test]
    fn flipping_any_bit_of_the_envelope_is_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
        dek in any::<[u8; 32]>(),
    ) {
        let sealed = seal(&SealInput::fresh(&plaintext, b"name.bin", dek)).map_err(fail)?;
        let mut tampered = sealed.bytes.clone();
        let index = position.index(tampered.len());
        tampered[index] ^= 1 << bit;
        match open(&tampered, sealed.header_length, dek, usize::MAX) {
            Ok(_) => prop_assert!(false, "bit {} of byte {} was not authenticated", bit, index),
            Err(error) => prop_assert!(is_rejection(&error.code), "unexpected {:?}", error.code),
        }
    }

    #[test]
    fn a_different_key_never_opens_an_envelope(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        dek in any::<[u8; 32]>(),
        other in any::<[u8; 32]>(),
    ) {
        prop_assume!(dek != other);
        let sealed = seal(&SealInput::fresh(&plaintext, b"", dek)).map_err(fail)?;
        let error = match open_sealed(&sealed, other) {
            Ok(_) => return Err(TestCaseError::fail("a wrong key opened the envelope")),
            Err(error) => error,
        };
        prop_assert!(is_rejection(&error.code), "unexpected {:?}", error.code);
    }

    #[test]
    fn truncating_or_extending_the_body_is_rejected(
        plaintext in prop::collection::vec(any::<u8>(), 0..2048),
        cut in 1usize..200,
        extra in prop::collection::vec(any::<u8>(), 1..64),
        dek in any::<[u8; 32]>(),
    ) {
        let sealed = seal(&SealInput::fresh(&plaintext, b"", dek)).map_err(fail)?;
        let body = sealed.body().len();
        let truncated = &sealed.bytes[..sealed.header_length + body.saturating_sub(cut)];
        prop_assert!(open(truncated, sealed.header_length, dek, usize::MAX).is_err());

        let mut extended = sealed.bytes.clone();
        extended.extend_from_slice(&extra);
        prop_assert!(open(&extended, sealed.header_length, dek, usize::MAX).is_err());
    }

    #[test]
    fn key_slots_round_trip_and_bind_every_parameter(
        dek in any::<[u8; 32]>(),
        master in any::<[u8; 32]>(),
        file_uuid in any::<[u8; 16]>(),
        slot_id in any::<u8>(),
    ) {
        let kind = SlotKind::Vault as u8;
        let kdf = KdfAlgorithm::HkdfSha256 as u16;
        let salt = random::random_salt();
        let wrapping =
            derive_file_wrapping_key(&SecretKey::new(master), &file_uuid, &salt, kind, slot_id)
                .map_err(fail)?;
        let context = KeySlotContext { file_uuid: &file_uuid, format_version: policy::FORMAT_VERSION };
        let (wrapped, nonce) =
            wrap_dek(&context, &SecretKey::new(dek), &wrapping, kind, slot_id, kdf, 0, 0, 0, &salt)
                .map_err(fail)?;

        let unwrapped = unwrap_dek(&context, &wrapped, &nonce, &wrapping, kind, slot_id, kdf, 0, 0, 0, &salt)
            .map_err(fail)?;
        prop_assert_eq!(unwrapped.expose(), &dek);

        let other_uuid = {
            let mut uuid = file_uuid;
            uuid[0] ^= 1;
            uuid
        };
        let moved = KeySlotContext { file_uuid: &other_uuid, format_version: policy::FORMAT_VERSION };
        let other_salt = {
            let mut changed = salt;
            changed[15] ^= 0x80;
            changed
        };
        let mut corrupt = wrapped;
        corrupt[0] ^= 1;
        let attempts = [
            unwrap_dek(&moved, &wrapped, &nonce, &wrapping, kind, slot_id, kdf, 0, 0, 0, &salt),
            unwrap_dek(&context, &wrapped, &nonce, &wrapping, kind, slot_id.wrapping_add(1), kdf, 0, 0, 0, &salt),
            unwrap_dek(&context, &wrapped, &nonce, &wrapping, SlotKind::RecoveryKey as u8, slot_id, kdf, 0, 0, 0, &salt),
            unwrap_dek(&context, &wrapped, &nonce, &wrapping, kind, slot_id, kdf, 0, 0, 0, &other_salt),
            unwrap_dek(&context, &corrupt, &nonce, &wrapping, kind, slot_id, kdf, 0, 0, 0, &salt),
            unwrap_dek(&context, &wrapped, &nonce, &SecretKey::new(random::random_key()), kind, slot_id, kdf, 0, 0, 0, &salt),
        ];
        for (case, attempt) in attempts.iter().enumerate() {
            prop_assert!(attempt.is_err(), "altered key-slot case {} unwrapped", case);
        }
    }
}

#[test]
fn every_byte_of_a_small_envelope_is_authenticated() -> CryptoResult<()> {
    let plaintext = pattern(300);
    let dek = random::random_key();
    let sealed = seal(&SealInput::fresh(&plaintext, b"every-byte.bin", dek))?;
    for index in 0..sealed.bytes.len() {
        let mut tampered = sealed.bytes.clone();
        tampered[index] ^= 0x01;
        let result = open(&tampered, sealed.header_length, dek, usize::MAX);
        assert!(
            result.is_err(),
            "byte {index} of {} is not authenticated (the header is {} bytes)",
            sealed.bytes.len(),
            sealed.header_length
        );
    }
    Ok(())
}

#[test]
fn records_cannot_be_reordered_dropped_or_moved_between_files() -> CryptoResult<()> {
    let chunk = policy::DEFAULT_CHUNK_SIZE as usize;
    let record = chunk + policy::AEAD_TAG_LENGTH;
    let plaintext = pattern(chunk * 2 + chunk / 2);
    let dek = random::random_key();
    let sealed = seal(&SealInput::fresh(&plaintext, b"", dek))?;
    assert_eq!(open_sealed(&sealed, dek)?.plaintext, plaintext);

    let mut swapped = sealed.bytes.clone();
    let start = sealed.header_length;
    let (first, second) = swapped[start..start + 2 * record].split_at_mut(record);
    first.swap_with_slice(second);
    let reordered = open(&swapped, sealed.header_length, dek, usize::MAX);
    assert!(reordered.is_err(), "swapped records decrypted");

    let mut dropped = sealed.header().to_vec();
    dropped.extend_from_slice(&sealed.body()[record..]);
    assert!(
        open(&dropped, sealed.header_length, dek, usize::MAX).is_err(),
        "a dropped record went unnoticed"
    );

    // The same key and plaintext under another file identity must not accept
    // this file's records.
    let other = seal(&SealInput::fresh(&plaintext, b"", dek))?;
    let mut spliced = other.header().to_vec();
    spliced.extend_from_slice(sealed.body());
    assert!(
        open(&spliced, other.header_length, dek, usize::MAX).is_err(),
        "records moved between files"
    );

    let reader = DecryptReader::new(sealed.header(), SecretKey::new(dek))?;
    let first_record = &sealed.body()[..record];
    assert_eq!(
        reader.decrypt_chunk_at(0, first_record)?,
        plaintext[..chunk]
    );
    assert!(
        reader.decrypt_chunk_at(1, first_record).is_err(),
        "a record was accepted at another index"
    );
    Ok(())
}

#[test]
fn identical_uploads_never_share_ciphertext_or_nonces() -> CryptoResult<()> {
    let plaintext = pattern(70_000);
    let dek = random::random_key();
    let first = seal(&SealInput::fresh(&plaintext, b"same", dek))?;
    let second = seal(&SealInput::fresh(&plaintext, b"same", dek))?;
    assert_ne!(
        first.body(),
        second.body(),
        "two uploads of one file produced equal ciphertext"
    );

    const SAMPLES: usize = 4096;
    let prefixes: HashSet<[u8; 16]> = (0..SAMPLES)
        .map(|_| random::random_nonce_prefix())
        .collect();
    let wrap_nonces: HashSet<[u8; 24]> =
        (0..SAMPLES).map(|_| random::random_wrap_nonce()).collect();
    let uuids: HashSet<[u8; 16]> = (0..SAMPLES).map(|_| random::random_uuid()).collect();
    assert_eq!(prefixes.len(), SAMPLES, "nonce prefix repeated");
    assert_eq!(wrap_nonces.len(), SAMPLES, "key-slot nonce repeated");
    assert_eq!(uuids.len(), SAMPLES, "file identity repeated");

    let master = SecretKey::new(random::random_key());
    let uuid = random::random_uuid();
    let dek_key = SecretKey::new(dek);
    let a = vault_slot(&master, &uuid, &dek_key)?;
    let b = vault_slot(&master, &uuid, &dek_key)?;
    assert_ne!(a.wrap_nonce, b.wrap_nonce, "rewrapping reused a nonce");
    assert_ne!(
        a.wrapped_dek, b.wrapped_dek,
        "rewrapping produced equal ciphertext"
    );
    Ok(())
}

#[test]
fn a_resumed_upload_reproduces_identical_ciphertext() -> CryptoResult<()> {
    let plaintext = pattern(300_000);
    let input = SealInput::fresh(&plaintext, b"resume.bin", random::random_key());
    let original = seal(&input)?;
    let session =
        EncryptionSession::from_header(original.header().to_vec(), SecretKey::new(input.dek))?;
    let resumed = stream(&plaintext, session)?;
    assert_eq!(resumed.bytes, original.bytes);
    Ok(())
}

#[test]
fn envelopes_outside_policy_are_refused_before_encryption() -> CryptoResult<()> {
    let dek = SecretKey::new(random::random_key());
    let uuid = random::random_uuid();
    let slot = vault_slot(&SecretKey::new(random::random_key()), &uuid, &dek)?;

    let no_slots = EncryptionSession::new_with_keys(
        1,
        Vec::new(),
        Vec::new(),
        SecretKey::new(*dek.expose()),
        uuid,
        [0; 16],
    );
    assert!(no_slots.is_err(), "an envelope without key slots was built");

    let duplicate = EncryptionSession::new_with_keys(
        1,
        vec![slot.clone(), slot.clone()],
        Vec::new(),
        SecretKey::new(*dek.expose()),
        uuid,
        [0; 16],
    );
    assert!(duplicate.is_err(), "duplicate key-slot IDs were accepted");

    let oversized = vec![0; policy::MAX_METADATA_LENGTH + 1];
    let too_large = EncryptionSession::new_with_keys(1, vec![slot], oversized, dek, uuid, [0; 16]);
    assert!(too_large.is_err(), "metadata above policy was accepted");
    Ok(())
}

#[test]
fn recovery_bundles_round_trip_and_reject_wrong_passphrases_and_tampering() -> CryptoResult<()> {
    let payload = pattern(512);
    let passphrase = b"correct horse battery staple";
    let bundle = create_recovery_bundle(&payload, passphrase)?;
    assert_eq!(import_recovery_bundle(&bundle, passphrase)?, payload);

    let second = create_recovery_bundle(&payload, passphrase)?;
    assert_ne!(
        bundle, second,
        "two exports of one vault produced equal bundles"
    );

    assert!(
        import_recovery_bundle(&bundle, b"correct horse battery stapler").is_err(),
        "a wrong passphrase imported"
    );

    let mut tampered = bundle.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        import_recovery_bundle(&tampered, passphrase).is_err(),
        "a tampered bundle imported"
    );

    assert!(
        create_recovery_bundle(&payload, b"short").is_err(),
        "a short passphrase was accepted"
    );
    assert!(
        create_recovery_bundle(&[], passphrase).is_err(),
        "an empty payload was accepted"
    );
    Ok(())
}
