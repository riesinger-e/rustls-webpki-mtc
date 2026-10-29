//! Inclusion proof evaluation

use crate::Error;
use crate::mtc::cert_format::MtcProof;
use crate::mtc::cert_format::tls_vec::OpaqueVec;
use pki_types::mtc::Hash;
use sha2::digest::FixedOutput;
use sha2::digest::Update;
use sha2::digest::array::{Array, ArraySize};
use sha2::digest::common::OutputSize;

/// Evaluate the inclusion proof. Returns the expected subtree hash.
/// Follows the MTC RFC, section 4.3.2.
pub(super) fn evaluate(
    mtc_proof: &MtcProof<'_>,
    index: u64,
    entry_hash: Hash,
) -> Result<Hash, Error> {
    match entry_hash {
        Hash::Sha256(val) => evaluate_inner::<sha2::Sha256, _>(mtc_proof, index, val)
            .map(Hash::Sha256)
            .ok_or(Error::MtcInvalidInclusionProof),
        _ => Err(Error::UnsupportedMtcHashAlgorithm),
    }
}

fn evaluate_inner<H: Default + Update + FixedOutput, const HASH_SIZE: usize>(
    mtc_proof: &MtcProof<'_>,
    index: u64,
    entry_hash: [u8; HASH_SIZE],
) -> Option<[u8; HASH_SIZE]>
where
    OutputSize<H>: ArraySize<ArrayType<u8> = [u8; HASH_SIZE]>,
{
    let &MtcProof {
        start,
        end,
        inclusion_proof: OpaqueVec(inclusion_proof),
        ..
    } = mtc_proof;

    // Step 1:
    // > Check that [start, end) is a valid subtree (Section 4.1), and that start <= index < end.
    // > If either does not hold, fail proof evaluation.
    if !(start <= end
        && start % u64::next_power_of_two(end - start) == 0
        && start <= index
        && index < end)
    {
        return None;
    }

    // Step 2:
    // > Set fn to index - start and sn to end - start - 1.
    let mut f_n = index - start;
    let mut s_n = end - start - 1;

    // Step 3:
    // > Set r to entry_hash
    let mut r: Array<u8, H::OutputSize> = entry_hash.into();

    // Step 4:
    // > For each value p in the inclusion_proof array
    // > ...
    // Split inclusion_proof into an array of hash values
    let (inclusion_proof, rem) = inclusion_proof
        .as_slice_less_safe()
        .as_chunks::<HASH_SIZE>();
    if !rem.is_empty() {
        return None;
    }

    for p in inclusion_proof.iter().map(|h| (*h).into()) {
        // Step 4.1
        // > If sn is 0, then stop the iteration and fail proof evaluation.
        if s_n == 0 {
            return None;
        }

        // Step 4.2
        // > If LSB(fn) is set, or if fn is equal to sn, then:
        // > ...
        if f_n & 0x1 == 0x1 || f_n == s_n {
            // Step 4.2.1
            // > Set r to HASH(0x01 || p || r).
            r = merkle_hash::<H>(p, r);

            // Step 4.2.2
            // > Until LSB(fn) is set, right-shift fn and sn equally.
            while f_n & 0x1 != 0x1 {
                f_n >>= 1;
                s_n >>= 1;
            }
        } else {
            // Step 4.2
            // > Otherwise: Set r to HASH(0x01 || r || p).
            r = merkle_hash::<H>(r, p);
        }

        // Step 4.3
        // > Finally, right-shift both fn and sn one time.
        f_n >>= 1;
        s_n >>= 1;
    }

    // Step 5: If sn is not zero, fail proof evaluation.
    if s_n != 0 {
        return None;
    }

    // Step 6: Return r as the expected subtree hash.
    Some(r.into())
}

/// Helper used in the evaluation
fn merkle_hash<H: Default + Update + FixedOutput>(
    left: Array<u8, H::OutputSize>,
    right: Array<u8, H::OutputSize>,
) -> Array<u8, H::OutputSize> {
    let mut hasher = H::default();
    Update::update(&mut hasher, &[0x01]);
    Update::update(&mut hasher, &left);
    Update::update(&mut hasher, &right);
    hasher.finalize_fixed()
}
