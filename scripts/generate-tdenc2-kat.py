#!/usr/bin/env python3
"""Independent reference encoder for TDENC2 known-answer vectors.

Builds envelopes from the format description alone (Docs/CRYPTO.md and the
constants in app/src-tauri/src/crypto/), using Python's `cryptography` package
for ChaCha20-Poly1305 and HKDF and a local HChaCha20 for the XChaCha20 subkey.
It shares no code with the Rust implementation, so a matching vector checks the
Rust encoder against a second implementation. Run:

    python3 scripts/generate-tdenc2-kat.py

and compare its output with the constants in app/src-tauri/tests/crypto_kat.rs.
"""
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MASK = 0xFFFFFFFF


def _rotl(value, count):
    return ((value << count) & MASK) | (value >> (32 - count))


def _quarter(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & MASK; state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK; state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK; state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK; state[b] = _rotl(state[b] ^ state[c], 7)


def hchacha20(key, nonce16):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _quarter(state, 0, 4, 8, 12); _quarter(state, 1, 5, 9, 13)
        _quarter(state, 2, 6, 10, 14); _quarter(state, 3, 7, 11, 15)
        _quarter(state, 0, 5, 10, 15); _quarter(state, 1, 6, 11, 12)
        _quarter(state, 2, 7, 8, 13); _quarter(state, 3, 4, 9, 14)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


# draft-irtf-cfrg-xchacha-03, section 2.2.1.
assert hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex() == (
    "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
)


def xchacha_seal(key, nonce24, message, aad):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\0" * 4 + nonce24[16:], message, aad)


def hkdf32(ikm, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(ikm)


MAGIC = b"TDENC2"
VERSION = 2
SUITE = 1
CHUNK_SIZE = 1_048_576
FINAL_INDEX = 2**64 - 2
METADATA_INDEX = 2**64 - 1


def nonce(prefix, index):
    return prefix + struct.pack("<Q", index)


def envelope(dek, file_uuid, prefix, slot, metadata, plaintext):
    metadata_ct_len = len(metadata) + 16 if metadata else 0
    header_len = 98 + len(slot) + metadata_ct_len
    core = (MAGIC + struct.pack("<H", VERSION) + file_uuid + struct.pack("<H", SUITE)
            + struct.pack("<IIIIQ", header_len, CHUNK_SIZE, len(slot), metadata_ct_len, len(plaintext))
            + prefix)
    assert len(core) == 66
    meta_ct = b""
    if metadata:
        meta_ct = xchacha_seal(hkdf32(dek, b"telegram-drive:metadata-enc:v2"), nonce(prefix, METADATA_INDEX),
                               metadata, b"telegram-drive:tdenc2:metadata" + core + slot)
    auth = hmac.new(hkdf32(dek, b"telegram-drive:header-auth:v2"),
                    b"telegram-drive:tdenc2:header-mac" + core + slot + meta_ct, hashlib.sha256).digest()
    header = core + auth + slot + meta_ct
    content_key = hkdf32(dek, b"telegram-drive:content-enc:v2")
    common = struct.pack("<H", VERSION) + file_uuid + auth
    body = b""
    count = 0
    for offset in range(0, len(plaintext), CHUNK_SIZE):
        piece = plaintext[offset:offset + CHUNK_SIZE]
        aad = (b"telegram-drive:tdenc2:chunk" + common
               + struct.pack("<QQIQ", count, offset, len(piece), len(plaintext)))
        body += xchacha_seal(content_key, nonce(prefix, count), piece, aad)
        count += 1
    final_plain = struct.pack("<IQ", count, len(plaintext)) + hashlib.sha256(plaintext).digest() + bytes(8)
    final_aad = b"telegram-drive:tdenc2:final" + common + struct.pack("<IQ", count, len(plaintext))
    final = xchacha_seal(content_key, nonce(prefix, FINAL_INDEX), final_plain, final_aad)
    return header, body + final, final


def pattern(length):
    return bytes((index * 31) % 251 for index in range(length))


DEK = bytes(range(32))
FILE_UUID = bytes(range(0x40, 0x50))
PREFIX = bytes(range(0x80, 0x90))
# Vault/HKDF key slot with fixed, opaque salt, wrap nonce and wrapped DEK. The
# DEK is supplied directly when decrypting, so the slot is never unwrapped.
SLOT = (bytes([1, 0]) + struct.pack("<HIII", 2, 0, 0, 0)
        + bytes([0x11] * 16) + bytes([0x22] * 24) + bytes([0x33] * 48))
assert len(SLOT) == 104

if __name__ == "__main__":
    header, rest, _ = envelope(DEK, FILE_UUID, PREFIX, SLOT, b"", b"")
    print("EMPTY_ENVELOPE =", (header + rest).hex())
    header, rest, _ = envelope(DEK, FILE_UUID, PREFIX, SLOT, b'{"name":"kat.txt"}', pattern(100))
    print("SMALL_ENVELOPE =", (header + rest).hex())
    header, rest, final = envelope(DEK, FILE_UUID, PREFIX, SLOT, b"", pattern(CHUNK_SIZE + 37))
    print("TWO_CHUNK_SHA256 =", hashlib.sha256(header + rest).hexdigest())
    print("TWO_CHUNK_LENGTH =", len(header + rest))
    print("TWO_CHUNK_FINAL_RECORD =", final.hex())
