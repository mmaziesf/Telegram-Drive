# Cryptography overview

This page maps each cryptographic claim the app makes to the code that implements it and the test that checks it. The byte-level format is specified in [TDENC2_FORMAT.md](TDENC2_FORMAT.md); this page does not repeat it.

> [!WARNING]
> The TDENC2 envelope and the vault have **not had an independent security audit**. The tests below show that the code behaves as described. They do not prove the design is sound.

All paths are relative to `app/src-tauri/src/crypto/`.

## Primitives

| Purpose | Primitive | Code |
| --- | --- | --- |
| Content, metadata and key wrapping | XChaCha20-Poly1305 (`chacha20poly1305` crate), 32-byte key, 24-byte nonce, 16-byte tag | `policy.rs` (`CIPHER_SUITE_XCHACHA20_POLY1305`, `XCHACHA_*`, `AEAD_TAG_LENGTH`) |
| Passphrase to key | Argon2id v0x13 (`argon2` crate), 32-byte output | `kdf.rs` `derive_passphrase_key` |
| Key separation | HKDF-SHA-256 with fixed per-purpose labels (`telegram-drive:…:v2`) | `kdf.rs` `derive_domain_key`, `domains` |
| Per-file wrapping key | HKDF-SHA-256 with the slot salt; the info string binds the file UUID, slot kind and slot ID | `kdf.rs` `derive_file_wrapping_key` |
| Header integrity | HMAC-SHA-256 over the envelope header | `envelope/header.rs` (`HmacSha256`) |
| Randomness | `rand::rng()`, a CSPRNG seeded from the operating system | `random.rs` |
| Secret memory | Keys and secret buffers are zeroed on drop (`zeroize`) | `secret.rs` (`impl Drop for SecretKey`, `SecretBytes`) |

## Parameters

- **Argon2id bounds** (`policy.rs`): memory 64–256 MiB, 3–100 iterations, parallelism 1–8. `validate_argon2_params` rejects any value outside them, including values read from a file, so a crafted file cannot request a weaker or a denial-of-service KDF.
- **Vault file**: written with the floor values, 64 MiB, 3 iterations and parallelism 1 (`vault/file.rs`, `encrypt_payload_with_key`).
- **Chunking**: 1 MiB by default, with 64 KiB to 16 MiB allowed (`policy.rs` `*_CHUNK_SIZE`). An envelope has at most 8 key slots, and its header and metadata are at most 64 KiB each.

## How a file is protected

1. Each upload gets a random 256-bit data key (DEK), a random 16-byte file UUID and a random 16-byte nonce prefix (`random.rs`).
2. **Chunk nonces.** Chunk *i* is sealed with the nonce `prefix ‖ i` (64-bit little-endian), built in `envelope/encrypt_reader.rs` `nonce`. Two indices are reserved: `u64::MAX − 1` for the final record and `u64::MAX` for the metadata (`policy.rs`). Every file has a fresh random prefix, so nonces are not reused under one DEK.
3. **Chunk binding.** Each chunk's associated data binds the format version, the file UUID, the header authenticator, the chunk index, the plaintext offset, the chunk length and the total length (`envelope/encrypt_reader.rs` `chunk_aad`). A chunk cannot be reordered, dropped, moved to another file or reused at another offset.
4. **Truncation.** The authenticated final record carries the chunk count, the plaintext length and a SHA-256 of the plaintext (`policy.rs` `FINAL_RECORD_PLAINTEXT_SIZE`). Decryption fails if this record is missing or does not match.
5. **Key slots.** The DEK is wrapped once per slot with XChaCha20-Poly1305 under a full random 24-byte nonce (`envelope/key_slot.rs` `wrap_dek`). The wrapping key comes from the vault master key or from a file passphrase, through `derive_file_wrapping_key`.
6. **Metadata protection.** When it is on, the original filename and MIME type are sealed under the DEK at the reserved metadata index. They are opened only after the header has been verified (`envelope/header.rs` `verify_and_decrypt_metadata`).

## Tests that back these claims

The adversarial and property suite is `app/src-tauri/tests/crypto_envelope.rs` (PR #5). Run it with `cargo test --locked --test crypto_envelope`. It checks the following:

| Claim | Test |
| --- | --- |
| Any plaintext and metadata round-trip, however the download is split | `any_plaintext_and_metadata_round_trip_in_any_fragmentation` |
| Every bit and every byte is authenticated | `flipping_any_bit_of_the_envelope_is_rejected`, `every_byte_of_a_small_envelope_is_authenticated` |
| A wrong key never yields plaintext | `a_different_key_never_opens_an_envelope` |
| Truncation and appended bytes are detected | `truncating_or_extending_the_body_is_rejected` |
| Chunks cannot be reordered, dropped or spliced in from another file | `records_cannot_be_reordered_dropped_or_moved_between_files` |
| No nonce or ciphertext reuse across uploads | `identical_uploads_never_share_ciphertext_or_nonces` |
| Key slots bind the UUID, slot ID, slot kind, salt and key | `key_slots_round_trip_and_bind_every_parameter` |
| Recovery bundles reject wrong passphrases and tampering | `recovery_bundles_round_trip_and_reject_wrong_passphrases_and_tampering` |

Known-answer tests are in `app/src-tauri/tests/crypto_kat.rs`; run them with `cargo test --locked --test crypto_kat`.

| Claim | Test |
| --- | --- |
| The header layout and authenticator, metadata encryption, chunk nonces (prefix plus little-endian record index), chunk and final-record AAD and the final record match an independent encoder (`scripts/generate-tdenc2-kat.py`, Python `cryptography` plus its own HChaCha20 checked against draft-irtf-cfrg-xchacha-03 section 2.2.1) | `reference_encoder_vectors_match_byte_for_byte`, `reference_encoder_vectors_decrypt_to_their_inputs` |
| HKDF-SHA-256 matches RFC 5869 | `hkdf_sha256_matches_rfc_5869_test_case_3` |
| A body longer or shorter than the declared size is rejected, as is an edited declared size | `a_body_that_differs_from_the_declared_size_is_rejected`, `an_edited_declared_size_is_rejected` |

The vectors use a fixed key slot whose wrapped DEK is opaque bytes, so they do not cover DEK wrapping; `key_slots_round_trip_and_bind_every_parameter` covers that. Fuzzing is not done yet.

## What is not encrypted by the app

- **Standard-mode uploads** go to Telegram unencrypted. From PR #1 onward, new uploads default to vault mode. Files uploaded before that stay as they are.
- **Transport and account metadata.** Telegram still sees the ciphertext size, the upload time, the account and the destination chat.
- **The Telegram session** (`telegram.session`, which holds the MTProto authorization key) is not encrypted by the app. From PR #2 onward it is owner-only (0600 inside a 0700 directory) on Unix-like systems. See [THREAT_MODEL.md](THREAT_MODEL.md#known-limitations).
