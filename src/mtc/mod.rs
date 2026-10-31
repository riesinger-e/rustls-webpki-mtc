//! Support for [Merkle Tree Certificates v7](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)

mod ca;
mod cert_format;
mod verify_signature;

pub(crate) use ca::remember_mtc_extension;
pub(crate) use verify_signature::verify_signature;

use core::cmp::Ordering;

/// Parse a big endian slice as an u64 while validating DER INTEGER encoding.
/// The slice is expected to only contain the payload --> no INTEGER TAG, no length encoding.
fn der_value_slice_as_u64_be(value: &[u8]) -> Option<u64> {
    const U64_BYTES: usize = size_of::<u64>();

    match value.len().cmp(&U64_BYTES) {
        Ordering::Less => {
            let mut buffer = [0u8; U64_BYTES];
            let start_idx = buffer.len() - value.len();
            buffer[start_idx..].copy_from_slice(value);
            Some(u64::from_be_bytes(buffer))
        }
        Ordering::Equal => {
            let mut buffer = [0u8; U64_BYTES];
            buffer.copy_from_slice(value);
            Some(u64::from_be_bytes(buffer))
        }
        // 1 leading 0x0 byte --> remove
        Ordering::Greater if value.len() == U64_BYTES + 1 && value[0] == 0x0 => {
            let mut buffer = [0u8; U64_BYTES];
            buffer.copy_from_slice(&value[1..]);
            Some(u64::from_be_bytes(buffer))
        }
        // additional byte, but not exactly 1 leading 0x0 byte
        Ordering::Greater => None,
    }
}
