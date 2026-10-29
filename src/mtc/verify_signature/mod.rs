//! Verify an MTC signature

mod cosigner;
mod entry_hash;
mod inclusion_proof;

use crate::der::Tag;
use crate::mtc::cert_format::MtcProof;
use crate::mtc::cert_format::tls_parsing::TlsParse;
use crate::mtc::der_value_slice_as_u64_be;
use crate::verify_cert::OidDecoder;
use crate::{Cert, DerTypeId, Error, der};
use alloc::vec::Vec;
use pki_types::SignatureVerificationAlgorithm;
use pki_types::mtc::{CosignerPolicy, Hash, MtcCa};

/// Implements certificate signature verification based on the MTC-RFC Draft, section 7.2
pub(crate) fn verify_signature(
    cert: &Cert<'_>,
    ca_mtc_config: &MtcCa<'_>,
    ca_spki: untrusted::Input<'_>,
    supported_algorithms: &[&dyn SignatureVerificationAlgorithm],
) -> Result<(), Error> {
    // Step 1:
    // >  Check that the TBSCertificate's signature field is id-alg-mtcProof with omitted parameters.
    // >  If this check fails, abort this process and fail verification.
    // The cert parsing ensures that TBSCertificates `signature` and the outer `signatureAlgorithm`
    // contain the same value.
    let signature_algorithm = cert.signed_data.algorithm;
    let signature_algorithm = signature_algorithm.read_all(
        Error::TrailingData(DerTypeId::SignatureAlgorithm),
        |reader| der::expect_tag(reader, Tag::OID),
    )?;
    if signature_algorithm.as_slice_less_safe() != pki_types::alg_id::MTC.as_ref() {
        return Err(Error::SignatureAlgorithmMismatch);
    }

    // Step 2:
    // > Decode the signatureValue as an MTCProof, as described in Section 6.2. If decoding fails,
    // > including if signatureValue is not a multiple of 8 bits or has extra data after the MTCProof,
    // > abort this process and fail verification.
    let mtc_proof = cert
        .signed_data
        .signature
        .read_all(Error::TrailingData(DerTypeId::Signature), |reader| {
            MtcProof::parse(reader).map_err(|_| Error::BadDer)
        })?;

    // Step 3:
    // > Let serial be the certificate's serial number. If serial is negative or greater than (2^64)-1,
    // > abort this process and fail verification.
    let serial = der_value_slice_as_u64_be(cert.serial()).ok_or(Error::BadDer)?;

    // Step 4:
    // > If serial is contained in one of the relying party's revoked ranges (Section 7.5), abort
    // > this process and fail verification.
    if ca_mtc_config
        .revoked_ranges
        .iter()
        .any(|range| range.contains(&serial))
    {
        return Err(Error::CertRevoked);
    }

    // Step 5:
    // > Let index be the least significant 48 bits of serial and let log_number be serial >> 48.
    // > If log_number is zero, abort this process and fail verification.
    let index = serial & ((1 << 48) - 1);
    // conversion is always safe because u64 >> 48 always results in a number that fits into u16
    #[allow(clippy::as_conversions)]
    let log_number = (serial >> 48) as u16;
    if log_number == 0 {
        return Err(Error::InvalidSerialNumber);
    }

    // Step 6: moved to just before step 12, as the computed value is only needed there

    // Steps 7, 8 and 9 are replaced with the one-pass hashing procedure described in the RFC,
    // section 7.2, below the original steps
    let entry_hash =
        entry_hash::compute(ca_mtc_config.hash_algorithm, &mtc_proof.extensions, cert)?;

    // Step 10:
    // > Let expected_subtree_hash be the result of evaluating the MTCProof's inclusion_proof for
    // > entry index, with hash entry_hash, of the subtree described by the MTCProof's start and end,
    // > following the procedure in Section 4.3.2. If evaluation fails, abort this process and fail
    // > verification.
    let expected_subtree_hash = inclusion_proof::evaluate(&mtc_proof, index, entry_hash)?;

    // Step 11:
    // > If log_number, start, and end match a trusted subtree (Section 7.4) for the CA, check that
    // > expected_subtree_hash is equal to the trusted subtree's hash. Return success if it matches
    // > and failure if it does not.
    for subtree in &ca_mtc_config.trusted_subtrees {
        if subtree.log_number != log_number
            || subtree.start != mtc_proof.start
            || subtree.end != mtc_proof.end
        {
            continue;
        }

        match (&subtree.hash, &expected_subtree_hash) {
            (Hash::Sha256(subtree_hash), Hash::Sha256(expected_subtree_hash)) => {
                return if subtree_hash == expected_subtree_hash {
                    Ok(())
                } else {
                    Err(Error::MtcInvalidInclusionProof)
                };
            }
            // hash algorithms do not match --> ignore
            _other => (),
        }
    }

    // Step 6:
    // > Let log_id be the log ID constructed from the CA ID in issuer and the log_number
    // > (Section 5.2).
    // We decode the ca id to its components
    let log_id = {
        let mut log_id: Vec<_> = OidDecoder::new_relative(ca_mtc_config.ca_id.as_ref()).collect();
        log_id.push(0);
        // u16 is always <= usize
        #[allow(clippy::as_conversions)]
        log_id.push(log_number as usize);
        log_id
    };

    // Step 12:
    // > Otherwise, check that the MTCProof's signatures contain a sufficient set of valid signatures
    // > from cosigners to satisfy the relying party's cosigner requirements (Section 7.3).
    // > Unrecognized cosigners MUST be ignored.
    let common_args = cosigner::VerifySignatureArgs {
        log_id,
        start: mtc_proof.start,
        end: mtc_proof.end,
        expected_subtree_hash,
        supported_algorithms,
    };

    // Verify CA signature
    let ca_signature = mtc_proof
        .signatures
        .0
        .iter()
        .find(|cs| cs.cosigner_id.0.as_slice_less_safe() == ca_mtc_config.ca_id.as_ref())
        .ok_or(Error::MtcMissingRequiredCosigner)?;

    cosigner::verify_signature_with_spki(
        &ca_mtc_config.ca_id,
        ca_spki,
        ca_signature.signature.0,
        &common_args,
    )?;

    match ca_mtc_config.cosigner_policy {
        // all done
        CosignerPolicy::CaOnly => Ok(()),
        CosignerPolicy::All => {
            // verify the signatures by other cosigners
            for cosigner in &ca_mtc_config.additional_cosigners {
                let signature = mtc_proof
                    .signatures
                    .0
                    .iter()
                    .find(|cs| cs.cosigner_id.0.as_slice_less_safe() == cosigner.id.as_ref())
                    .ok_or(Error::MtcMissingRequiredCosigner)?;

                cosigner::verify_signature(cosigner, signature.signature.0, &common_args)?
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Cert;
    use crate::Error;
    use crate::mtc::verify_signature::verify_signature;
    use crate::verify_cert::OidDecoder;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use base64::Engine;
    use base64::engine::GeneralPurposeConfig;
    use pki_types::mtc::{Cosigner, CosignerPolicy, Hash, TrustedSubtree};
    use pki_types::{CertificateDer, TrustAnchor, alg_id};

    macro_rules! cert_from_name {
        ($name:literal) => {
            Cert::from_der(untrusted::Input::from(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/mtc/",
                $name
            ))))
        };
    }

    fn base64_decode(
        val: &[u8],
        engine: &mut Option<base64::engine::GeneralPurpose>,
    ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let engine = engine.get_or_insert_with(|| {
            let alphabet = base64::alphabet::STANDARD;
            base64::engine::GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new())
        });

        Ok(engine.decode(val)?)
    }

    fn read_ca_cert() -> Result<TrustAnchor<'static>, Box<dyn core::error::Error>> {
        fn sha256_from_base64(
            val: &[u8],
            engine: &mut Option<base64::engine::GeneralPurpose>,
        ) -> Result<Hash, Box<dyn core::error::Error>> {
            Ok(Hash::Sha256(
                base64_decode(val, engine)?.as_slice().try_into()?,
            ))
        }

        // generated with the official MTC RFC demo, ca_cert.pem
        //   ./demo generate
        //   openssl x509 -outform der -in ca_cert.pem -out ca-cert.der
        static CA_CERT_BIN: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/mtc/ca-cert.der"
        ));
        static CA_CERT_DER: CertificateDer<'static> = CertificateDer::from_slice(CA_CERT_BIN);

        // landmarks are the output of ./demo generate
        let mut engine = None;
        let e = &mut engine;
        let landmarks = vec![
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"h8Kw2BqVjlYaB3esivVVSwmRQfwVIb6E71DEeK3YQwc=", e)?,
                0,
                32,
            )
            .unwrap(),
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"aQ7rLTwjwLuYX6KLJpERloBQERVSWgFUxcOiSIwvNPg=", e)?,
                32,
                34,
            )
            .unwrap(),
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"blLA+9WDzuzi1pEWyHy06XW17rgrWhiKbDaV7WxXzpw=", e)?,
                0,
                1024,
            )
            .unwrap(),
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"xc/+sJddkjD4FL8rGdrkbMItGKsWrhfhIRp8vYprdiI=", e)?,
                1024,
                2036,
            )
            .unwrap(),
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"H89Du5MigjGfW+Dd+K2HSnMi5S5JPBeLAf+IoZHO8jY=", e)?,
                2032,
                2048,
            )
            .unwrap(),
            TrustedSubtree::new(
                1,
                sha256_from_base64(b"NI0xeg7ALqrMDJYtMMIcnU6b5E4dFYdWd6dI8yH2wh0=", e)?,
                2048,
                2122,
            )
            .unwrap(),
        ];

        let ca = crate::trust_anchor::anchor_from_trusted_mtc_cert(
            &CA_CERT_DER,
            CosignerPolicy::All,
            &[],
            Vec::new(),
            landmarks,
        )?;

        Ok(ca)
    }

    // verify the existing OID decoder functionality
    #[test]
    fn verify_oid_decoder() {
        // we know form other test that the as_bytes() representation of this OID is correct
        let oid = x509_parser::asn1_rs::oid!(rel 32473.1);

        let decoded_oid: Vec<_> = OidDecoder::new_relative(oid.as_bytes()).collect();
        assert_eq!(decoded_oid.as_slice(), &[32473, 1]);
    }

    #[test]
    fn test_landmark_cert_verification() -> Result<(), Box<dyn core::error::Error>> {
        // generated with the official MTC RFC demo, cert_10_12.pem
        //   ./demo generate
        //   openssl x509 -outform der -in cert_10_12.pem -out cert-landmark.der
        let cert = cert_from_name!("cert-landmark.der")?;
        let ca = read_ca_cert()?;

        assert!(ca.mtc_config.is_some());

        verify_signature(
            &cert,
            &ca.mtc_config.unwrap(),
            ca.subject_public_key_info.as_ref().into(),
            crate::ALL_VERIFICATION_ALGS,
        )?;

        Ok(())
    }

    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_standalone_cert_verification() -> Result<(), Box<dyn core::error::Error>> {
        // generated with the official MTC RFC demo, cert_10_3.pem
        //   ./demo generate
        //   openssl x509 -outform der -in cert_10_3.pem -out cert-standalone-simple.der
        let cert = cert_from_name!("cert-standalone-simple.der")?;
        let ca_cert = read_ca_cert()?;

        assert!(ca_cert.mtc_config.is_some());
        verify_signature(
            &cert,
            &ca_cert.mtc_config.unwrap(),
            ca_cert.subject_public_key_info.as_ref().into(),
            crate::ALL_VERIFICATION_ALGS,
        )?;

        Ok(())
    }

    /// Test that erronous cert formats are recognized
    #[test]
    fn test_cert_format() -> Result<(), Box<dyn core::error::Error>> {
        let certs = [cert_from_name!("cert_10_1.der")];

        for cert in certs {
            assert_eq!(cert.map(|_| ()), Err(Error::BadDer))
        }

        Ok(())
    }

    /// Test that all demo cert verifications deliver the expected results
    #[test]
    #[cfg(feature = "aws-lc-rs")]
    fn test_cert_verification_complex() -> Result<(), Box<dyn core::error::Error>> {
        let mut b64e = None;
        macro_rules! cosigner {
            (rel $($oid:literal ).*, $alg_id: expr, $private_key: literal, $encoder: ident) => {
                {
                    use aws_lc_rs::signature::KeyPair;
                    use aws_lc_rs::encoding::AsDer;
                    use aws_lc_rs::signature;

                    let private_key = base64_decode($private_key, &mut $encoder)?;
                    let public_key = match $alg_id {
                        pki_types::alg_id::ML_DSA_44 => signature::PqdsaKeyPair::from_pkcs8(&signature::ML_DSA_44_SIGNING, &private_key)?.public_key().as_der(),
                        pki_types::alg_id::ML_DSA_65 => signature::PqdsaKeyPair::from_pkcs8(&signature::ML_DSA_65_SIGNING, &private_key)?.public_key().as_der(),
                        pki_types::alg_id::ML_DSA_87 => signature::PqdsaKeyPair::from_pkcs8(&signature::ML_DSA_87_SIGNING, &private_key)?.public_key().as_der(),
                        other => unimplemented!("Get public key from private key with algorithm {other:?}"),
                    }?;
                    let public_key = alloc::borrow::Cow::from(public_key.as_ref().to_vec());

                    let id = x509_parser::asn1_rs::oid!(rel $($oid).*).as_bytes().to_vec();
                    Cosigner {
                        id: id.into(),
                        signature_algorithm: $alg_id,
                        public_key,
                    }
                }
            }
        }

        // cosigners from the RFC demo, mtc.json
        let cosigners = [
            cosigner!(rel 32473.2.2, alg_id::ML_DSA_65, b"MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f", b64e),
            cosigner!(rel 32473.2.3, alg_id::ML_DSA_87, b"MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f", b64e),
            cosigner!(rel 32473.3.1, alg_id::ML_DSA_44, b"MDQCAQAwCwYJYIZIAWUDBAMRBCKAIFjaimQAg5B4OTbZNTnt/YcmjPmbijnynHnvsyPLk8Sg", b64e),
            cosigner!(rel 32473.3.2, alg_id::ML_DSA_44, b"MDQCAQAwCwYJYIZIAWUDBAMRBCKAIIGtnTZ2R5Pgp/LvgBo1ZTPJwaKcFmxe8r0wPhNvs8Sa", b64e),
            cosigner!(rel 32473.3.3, alg_id::ML_DSA_44, b"MDQCAQAwCwYJYIZIAWUDBAMRBCKAICTZRYfEBWrOAIYqcvvXMwD4WUiGtodBvmL6yurbazOH", b64e),
            cosigner!(rel 32473.3.4, alg_id::ML_DSA_44, b"MDQCAQAwCwYJYIZIAWUDBAMRBCKAIHdUCNv4IVovnAvS64yzdYpQhMMiT8OcHpFU2zF6ByZr", b64e),
        ];

        // all certs generated with the official demo
        //  ./demo generate
        //  openssl x509 -outform -der -in <CERT>.pem -out <CERT>.der
        let certs = [
            (
                cert_from_name!("cert_10_0.der")?,
                vec![cosigners[0].clone()],
                Ok(()),
            ),
            // deliberate format error
            // cert_from_name!("cert_10_1.der"),
            (
                cert_from_name!("cert_10_2.der")?,
                vec![cosigners[0].clone()],
                Err(Error::InvalidSignatureForPublicKey),
            ),
            (cert_from_name!("cert_10_3.der")?, Vec::new(), Ok(())),
            (
                cert_from_name!("cert_10_4.der")?,
                vec![cosigners[2].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_5.der")?,
                vec![cosigners[3].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_6.der")?,
                vec![cosigners[4].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_7.der")?,
                vec![cosigners[5].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_8.der")?,
                cosigners.to_vec(),
                Err(Error::MtcMissingRequiredCosigner),
            ),
            (
                cert_from_name!("cert_10_9.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_10.der")?,
                Vec::new(),
                Err(Error::MtcMissingRequiredCosigner),
            ),
            (
                cert_from_name!("cert_10_11.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_11.der")?,
                vec![cosigners[1].clone(), cosigners[2].clone()],
                Err(Error::MtcMissingRequiredCosigner),
            ),
            (
                cert_from_name!("cert_10_12.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_13.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_10_14.der")?,
                vec![cosigners[0].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_32_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_32_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_33_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_33_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_2034_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_2034_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_2035_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_2035_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_2035_2.der")?,
                cosigners.to_vec(),
                Err(Error::MtcInvalidInclusionProof),
            ),
            (
                cert_from_name!("cert_2078_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_2078_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
            (
                cert_from_name!("cert_2121_0.der")?,
                vec![cosigners[1].clone()],
                Ok(()),
            ),
            (
                cert_from_name!("cert_2121_1.der")?,
                cosigners.to_vec(),
                Ok(()),
            ),
        ];

        let ca_cert = read_ca_cert()?;

        assert!(ca_cert.mtc_config.is_some());
        let mtc_config = ca_cert.mtc_config.unwrap();
        let spki = ca_cert.subject_public_key_info.as_ref().into();

        for (i, (cert, cosigners, result)) in certs.into_iter().enumerate() {
            let mut mtc_config = mtc_config.clone();
            mtc_config.additional_cosigners = cosigners;
            std::eprintln!("{i}");
            assert_eq!(
                verify_signature(&cert, &mtc_config, spki, crate::ALL_VERIFICATION_ALGS),
                result
            );
        }

        Ok(())
    }
}
