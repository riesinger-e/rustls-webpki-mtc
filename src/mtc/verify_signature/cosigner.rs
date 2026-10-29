//! Signature verification with cosigners

use crate::signed_data::SubjectPublicKeyInfo;
use crate::verify_cert::OidDecoder;
use crate::{Error, UnsupportedSignatureAlgorithmForPublicKeyContext, der};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pki_types::mtc::{Cosigner, Hash};
use pki_types::{SignatureVerificationAlgorithm, alg_id};

/// Common args to the verify_signature* functions.
pub(super) struct VerifySignatureArgs<'a> {
    /// Log ID
    pub(super) log_id: Vec<usize>,
    /// Inclusive start idx of the subtree
    pub(super) start: u64,
    /// Exclusive end idx of the subtree
    pub(super) end: u64,
    /// Expected subtree hash
    pub(super) expected_subtree_hash: Hash,
    /// Supported cryptographic algorithms
    pub(super) supported_algorithms: &'a [&'a dyn SignatureVerificationAlgorithm],
}

/// Verify cosigner signatures.
/// Based on the RFC, section 7.2 step 12 and section 5.3.1.
pub(super) fn verify_signature(
    cosigner: &Cosigner<'_>,
    signature_value: untrusted::Input<'_>,
    common_args: &VerifySignatureArgs<'_>,
) -> Result<(), Error> {
    let Cosigner {
        id: cosigner_id,
        signature_algorithm,
        public_key,
    } = cosigner;

    verify_signature_impl(
        cosigner_id,
        signature_algorithm.as_ref(),
        public_key,
        signature_value,
        common_args,
    )
}

/// Verify cosigner signatures.
/// Just like [verify_signature], but supports taking the cosigner key and algorithm from a Cert SPKI DER structure.
pub(super) fn verify_signature_with_spki(
    cosigner_id: &[u8],
    spki: untrusted::Input<'_>,
    signature_value: untrusted::Input<'_>,
    common_args: &VerifySignatureArgs<'_>,
) -> Result<(), Error> {
    let SubjectPublicKeyInfo {
        algorithm_id_value,
        key_value,
    } = der::read_all::<SubjectPublicKeyInfo<'_>>(spki)?;

    verify_signature_impl(
        cosigner_id,
        algorithm_id_value.as_slice_less_safe(),
        key_value.as_slice_less_safe(),
        signature_value,
        common_args,
    )
}

fn verify_signature_impl(
    cosigner_id: &[u8],
    signature_algorithm: &[u8],
    public_key: &[u8],
    signature_value: untrusted::Input<'_>,
    common_args: &VerifySignatureArgs<'_>,
) -> Result<(), Error> {
    let decoded_cosigner_id: Vec<_> = OidDecoder::new_relative(cosigner_id).collect();
    let &VerifySignatureArgs {
        ref log_id,
        start,
        end,
        ref expected_subtree_hash,
        supported_algorithms,
    } = common_args;

    let cosigned_subtree = create_cosigned_subtree(
        &decoded_cosigner_id,
        log_id,
        start,
        end,
        expected_subtree_hash,
    )?;

    // Signature algorithm selection logic is based on the RFC repository, `/demo/encode.go`,
    // lines 46-51 and lines 273-287.
    // --> Find a suitable public_key_alg_id for the signature_algorithm that results in the
    // same selection that the RFC demo makes.
    const ECDSA_SHA256_SLICE: &[u8] = alg_id::ECDSA_SHA256.as_slice();
    const ECDSA_SHA384_SLICE: &[u8] = alg_id::ECDSA_SHA384.as_slice();

    let public_key_alg_id = match signature_algorithm {
        // 2 special cases where signature_algorithm and public_key_alg_id differ (from the demo)
        ECDSA_SHA256_SLICE => alg_id::ECDSA_P256.as_slice(),
        ECDSA_SHA384_SLICE => alg_id::ECDSA_P384.as_slice(),
        // Rest: use the signature_algorithm as public_key_alg_id - works for ED25519 and ML_DSA*.
        // Probably doesn't work with RSA etc. - if you use RSA with MTC certs, you don't get the
        // use case.
        other => other,
    };

    // find algorithm with both identifiers matching
    let algorithm = supported_algorithms
        .iter()
        .find(|alg| {
            alg.signature_alg_id().as_slice() == signature_algorithm
                && alg.public_key_alg_id().as_slice() == public_key_alg_id
        })
        .ok_or_else(|| {
            Error::UnsupportedSignatureAlgorithmForPublicKeyContext(
                UnsupportedSignatureAlgorithmForPublicKeyContext {
                    #[cfg(feature = "alloc")]
                    signature_algorithm_id: signature_algorithm.to_vec(),
                    #[cfg(feature = "alloc")]
                    public_key_algorithm_id: public_key_alg_id.to_vec(),
                },
            )
        })?;

    // verify the signature
    algorithm
        .verify_signature(
            public_key,
            cosigned_subtree.as_slice(),
            signature_value.as_slice_less_safe(),
        )
        .map_err(|_| Error::InvalidSignatureForPublicKey)
}

/// Create the cosigned subtree, already encoded in the TLS presentation language
fn create_cosigned_subtree(
    cosigner_id: &[usize],
    log_id: &[usize],
    start: u64,
    end: u64,
    subtree_hash: &Hash,
) -> Result<Vec<u8>, Error> {
    // section 7.2 step 12:
    // > Signatures are verified as described in Section 5.3.1. For each signature verification, the CosignedSubtree structure is constructed as follows:
    // > 1. Set the CosignedSubtree's cosigner_name based on the cosigner ID as described in Section 5.3.1.
    // > 2. Set the CosignedSubtree's timestamp to zero.
    // > 3. Set the CosignedSubtree's log_origin based on log_id as described in Section 5.3.1.
    // > 4. Set the CosignedSubtree's start and end to the MTCProof's start and end, respectively.
    // > 5. Set the CosignedSubtree's subtree_hash to expected_subtree_hash.

    fn create_oid_string(oid_parts: &[usize]) -> String {
        static OID_BASE_STRING: &str = "oid/1.3.6.1.4.1";

        let mut val = String::from(OID_BASE_STRING);
        for part in oid_parts {
            val.push('.');
            val.push_str(part.to_string().as_str());
        }
        val
    }

    let cosigner_name = create_oid_string(cosigner_id).into_bytes();
    if cosigner_name.len() > u8::MAX.into() {
        return Err(Error::InvalidSignatureForPublicKey);
    }
    let log_origin = create_oid_string(log_id).into_bytes();
    if log_origin.len() > u8::MAX.into() {
        return Err(Error::InvalidSignatureForPublicKey);
    }

    let mut encoded = Vec::new();
    // label
    encoded.extend(b"subtree/v1\n\0");

    // cosigner_name
    // length is verified to be fit into one byte
    #[allow(clippy::as_conversions)]
    encoded.push(cosigner_name.len() as u8);
    encoded.extend(cosigner_name);

    // timestamp
    encoded.extend(0u64.to_be_bytes());

    // log_origin
    // length is verified to be fit into one byte
    #[allow(clippy::as_conversions)]
    encoded.push(log_origin.len() as u8);
    encoded.extend(log_origin);

    // start
    encoded.extend(start.to_be_bytes());
    // end
    encoded.extend(end.to_be_bytes());

    // subtree_hash
    match subtree_hash {
        Hash::Sha256(value) => encoded.extend(value),
        _other => return Err(Error::UnsupportedMtcHashAlgorithm),
    }

    #[cfg(all(test, feature = "std"))]
    {
        std::println!("Subtree hex repr: {:02x?}", encoded.as_slice());
    }

    Ok(encoded)
}
