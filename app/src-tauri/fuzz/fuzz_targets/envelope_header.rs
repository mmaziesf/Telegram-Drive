//! Parses arbitrary bytes as a TDENC2 header and, when that succeeds, drives
//! metadata verification and decrypter setup with a fixed key. Any panic,
//! overflow or out-of-bounds access is a bug; errors are expected.
#![no_main]

use app_lib::crypto::envelope::decrypt_reader::DecryptReader;
use app_lib::crypto::envelope::EnvelopeHeader;
use app_lib::crypto::secret::SecretKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = EnvelopeHeader::parse(data) {
        let _ = header.core.chunk_count();
        let _ = header.raw_bytes().len();
        let _ = header.verify_and_decrypt_metadata(&SecretKey::new([7; 32]));
    }
    let _ = DecryptReader::new(data, SecretKey::new([7; 32]));
});
