use crate::der::Tag;
use crate::mtc::cert_format::MtcLogEntryExtensions;
use crate::{Cert, Error, der};
use pki_types::mtc::{Hash, HashAlgorithm};
use sha2::digest::FixedOutput;
use sha2::digest::Update;
use sha2::digest::array::ArraySize;
use sha2::digest::common::OutputSize;

/// Compute the MTC entry hash for signature verification
pub(super) fn compute(
    hash_algorithm: HashAlgorithm,
    extensions: &MtcLogEntryExtensions<'_>,
    cert: &Cert<'_>,
) -> Option<Hash> {
    match hash_algorithm {
        HashAlgorithm::Sha256 => {
            compute_entry_hash_inner::<sha2::Sha256, _>(extensions, cert).map(Hash::Sha256)
        }
        _ => None,
    }
}

/// Compute entry hash using the given hash algorithm
fn compute_entry_hash_inner<H: Default + Update + FixedOutput, const HASH_SIZE: usize>(
    mtc_extensions: &MtcLogEntryExtensions<'_>,
    cert: &Cert<'_>,
) -> Option<[u8; HASH_SIZE]>
where
    OutputSize<H>: ArraySize<ArrayType<u8> = [u8; HASH_SIZE]>,
{
    /// Value `tbs_cert_entry` of the enum `MTCLogEntryType`
    const TBS_LOG_ENTRY_TYPE_TBS_CERT_ENTRY: u16 = 0x1;

    // see RFC, section 7.2 at the bottom
    let mut hasher = H::default();
    // Step 2
    hasher.update(&[0x00]);
    // Step 3
    hasher.update(mtc_extensions.vec_header.as_slice_less_safe());
    hasher.update(mtc_extensions.vec_data.as_slice_less_safe());
    // Step 4
    hasher.update(&u16::to_be_bytes(TBS_LOG_ENTRY_TYPE_TBS_CERT_ENTRY));

    // Step 5
    // Version: always v3 (=2) - only version supported in this crate
    hasher.update(&der::asn1_wrap(
        Tag::ContextSpecificConstructed0,
        cert.version.as_slice_less_safe(),
    ));
    // Issuer
    hasher.update(&der::asn1_wrap(Tag::Sequence, cert.issuer()));
    // Validity
    hasher.update(&der::asn1_wrap(
        Tag::Sequence,
        cert.validity.as_slice_less_safe(),
    ));
    // Subject
    hasher.update(&der::asn1_wrap(Tag::Sequence, cert.subject()));

    // Step 6: SPKI algorithm
    let spki_algorithm = cert
        .spki
        .read_all(Error::BadDer, |reader| {
            let algorithm = der::expect_tag(reader, Tag::Sequence)?;
            // we don't care about the public key itself
            reader.skip_to_end();
            Ok(algorithm)
        })
        .ok()?;
    hasher.update(&der::asn1_wrap(
        Tag::Sequence,
        spki_algorithm.as_slice_less_safe(),
    ));

    // Step 7, 8, 9
    let spki_hash = {
        let mut hasher = H::default();
        hasher.update(cert.subject_public_key_info().as_ref());
        hasher.finalize_fixed()
    };
    hasher.update(&der::asn1_wrap(Tag::OctetString, spki_hash.as_slice()));

    // Step 10: only extensions is supported. This crate does not recognize issuerUniqueID nor subjectUniqueID
    if let Some(ext) = cert.extensions {
        hasher.update(&der::asn1_wrap(
            Tag::ContextSpecificConstructed3,
            ext.as_slice_less_safe(),
        ));
    }

    // Step 11: finalize
    Some(hasher.finalize_fixed().into())
}
