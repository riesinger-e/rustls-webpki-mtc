mod format;

use crate::x509::set_extension_once;
use alloc::borrow::Cow;
use pki_types::mtc::{CosignerPolicy, HashAlgorithm, MtcCa};
use std::prelude::rust_2015::Vec;
use std::range::RangeInclusive;

/// Remember the extension if it is an MTC extension.
/// Returns Ok(true) if the given extension is handled, else Ok(false).
/// Extension format errors return Err(...)
pub(crate) fn remember_mtc_extension<'a>(
    cert: &mut crate::Cert<'a>,
    extension: &crate::x509::Extension<'a>,
) -> Result<bool, crate::Error> {
    let hash_algorithm =
        if extension.id.as_slice_less_safe() == HashAlgorithm::Sha256.extension_oid() {
            HashAlgorithm::Sha256
        } else {
            // early return: this is not an MTC extension
            return Ok(false);
        };

    if !extension.critical {
        return Err(crate::Error::ExtensionValueInvalid);
    }

    set_extension_once(&mut cert.mtc_ca, || {
        let extension = format::Extension::parse(extension.value)?;
        let ca_id = format::subject_extract_cosigner_id(cert.subject)?;

        Ok(MtcCa {
            hash_algorithm,
            ca_id: Cow::Borrowed(ca_id.as_slice_less_safe()),
            signature_algorithm: Cow::Borrowed(extension.algorithm_identifier.as_slice_less_safe()),
            revoked_ranges: alloc::vec![
                RangeInclusive::from(0..=(extension.min_serial - 1)),
                RangeInclusive::from((extension.max_serial + 1)..=u64::MAX),
            ],
            cosigner_policy: CosignerPolicy::default(),
            additional_cosigners: Vec::new(),
            trusted_subtrees: Vec::new(),
        })
    })?;

    Ok(true)
}

#[cfg(test)]
mod test {
    use crate::Cert;
    use crate::mtc::ca::HashAlgorithm;
    use std::range::RangeInclusive;

    // check that an MTC CA cert is parsed correctly
    #[test]
    fn test_ca_cert_parsing() {
        // generated with the official MTC RFC demo, cert_10_3.pem
        //   ./demo generate
        //   openssl x509 -outform der -in ca_cert.pem -out ca-cert.der
        let cert_der = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/mtc/ca-cert.der"
        ));
        let cert = Cert::from_der(untrusted::Input::from(cert_der)).unwrap();

        // values taken from the MTC RFC demo, `mtc.json`
        match cert.mtc_ca {
            Some(mtc) => {
                assert_eq!(mtc.hash_algorithm, HashAlgorithm::Sha256);
                assert_eq!(
                    mtc.ca_id.as_ref(),
                    x509_parser::asn1_rs::oid!(rel 32473.1).as_bytes()
                );
                assert_eq!(
                    mtc.signature_algorithm.as_ref(),
                    &*pki_types::alg_id::ML_DSA_44
                );
                assert_eq!(mtc.revoked_ranges.len(), 2);
                assert_eq!(
                    mtc.revoked_ranges[0],
                    RangeInclusive::from(0..=((1 << 48) - 1))
                );
                assert_eq!(
                    mtc.revoked_ranges[1],
                    RangeInclusive::from(((5 << 48) + 281474976710655 + 1)..=u64::MAX)
                );
            }
            None => panic!("{} is None", stringify!(cert.mtc_ca)),
        }
    }

    // check that a CA cert that is not an MTC is also still parsed correctly
    #[test]
    fn test_ca_cert_parsing_non_mtc() {
        let cert_der = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/amazon/AmazonRootCA1.cer"
        ));
        let cert = Cert::from_der(untrusted::Input::from(cert_der)).unwrap();
        assert!(cert.mtc_ca.is_none());
    }
}
