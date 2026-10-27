# TDENC2 fuzz targets

Coverage-guided fuzzing for the TDENC2 envelope parser and decrypter. This is a
research harness: it is not part of the app build, CI or the release, and it
keeps its own Cargo workspace and lockfile.

| Target | What it drives |
| --- | --- |
| `envelope_header` | `EnvelopeHeader::parse` on arbitrary bytes; on success, `chunk_count`, `raw_bytes` and metadata verification with a fixed key; then `DecryptReader::new`. |
| `envelope_decrypt` | A valid header built once with fixed keys, followed by input bytes as ciphertext, fed in fragments sized by the first byte, plus `decrypt_chunk_at`. It aborts if a forged body authenticates or yields any plaintext. |

## Running

Needs a nightly toolchain and `cargo-fuzz` (`cargo install cargo-fuzz`).

```sh
cd app/src-tauri/fuzz
mkdir -p corpus/envelope_header
# Seed the header target with the known-answer envelopes so it gets past the
# magic and version checks.
python3 ../../../scripts/generate-tdenc2-kat.py | python3 -c '
import sys
for line in sys.stdin:
    key, _, value = line.partition(" = ")
    if key in ("EMPTY_ENVELOPE", "SMALL_ENVELOPE"):
        open("corpus/envelope_header/" + key.lower(), "wb").write(bytes.fromhex(value.strip()))
'
cargo +nightly fuzz run envelope_header -- -max_total_time=600
cargo +nightly fuzz run envelope_decrypt -- -max_total_time=600
```

`corpus/`, `artifacts/` and `target/` are ignored. A crashing input saved under
`artifacts/` should become a native regression test before it is fixed.
