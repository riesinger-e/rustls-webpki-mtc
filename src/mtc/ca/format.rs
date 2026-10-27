//! Types and helpers for the format of MTC CA certificates, section 5.5

use crate::der;
use crate::der::{Tag, nonnegative_integer};
use crate::mtc::der_value_slice_as_u64_be;
use crate::{DerTypeId, Error};

/// extract the CA ID (= cosigner ID) from the CA subject
pub(in crate::mtc) fn subject_extract_cosigner_id(
    subject: untrusted::Input<'_>,
) -> Result<untrusted::Input<'_>, Error> {
    /// Identifies a subject containing a CA (cosigner) ID
    static MTC_CA_OID: [u8; 8] = oid!(1, 3, 6, 1, 5, 5, 7, 25, 3);

    // parse the subject as a PKIX distinguished Name (section 5.1)
    let (oid, cosigner_id) = subject.read_all(Error::BadDer, |reader| {
        der::nested(reader, Tag::Set, Error::BadDer, |reader| {
            der::nested(reader, Tag::Sequence, Error::BadDer, |reader| {
                let oid = der::expect_tag(reader, Tag::OID)?;
                let cosigner_id = der::expect_tag(reader, Tag::RelativeOID)?;

                Ok((oid, cosigner_id))
            })
        })
    })?;

    if oid.as_slice_less_safe() != MTC_CA_OID.as_slice() {
        // wrong attribute type
        return Err(Error::MalformedMtcCaId);
    }

    Ok(cosigner_id)
}

// min and max values for the serial in Extension
const MIN_SERIAL: u64 = 281474976710656;
const MAX_SERIAL: u64 = 18446744073709551615;

/// Format of the extension value MTCCertificationAuthority
pub(in crate::mtc) struct Extension<'a> {
    /// Algorithm identifier in the same format as [AlgorithmIdentifier](pki_types::AlgorithmIdentifier)
    pub algorithm_identifier: untrusted::Input<'a>,
    pub min_serial: u64,
    pub max_serial: u64,
}

impl<'a> Extension<'a> {
    /// Parse the extension value
    pub(in crate::mtc) fn parse(value: untrusted::Input<'a>) -> Result<Self, Error> {
        let (sig_alg, min_serial, max_serial) =
            value.read_all(Error::TrailingData(DerTypeId::Extension), |reader| {
                // outer sequence
                der::nested(
                    reader,
                    Tag::Sequence,
                    Error::ExtensionValueInvalid,
                    |reader| {
                        let sig_alg = der::expect_tag(reader, Tag::Sequence)?;
                        let min_serial = der_parse_u64(reader)?;
                        let max_serial = der_parse_u64(reader)?;

                        Ok((sig_alg, min_serial, max_serial))
                    },
                )
            })?;

        // validate serial constraints
        if !(MIN_SERIAL..=MAX_SERIAL).contains(&min_serial) {
            return Err(Error::ExtensionValueInvalid);
        }

        if (!MIN_SERIAL..=MAX_SERIAL).contains(&max_serial) {
            return Err(Error::ExtensionValueInvalid);
        }

        Ok(Self {
            algorithm_identifier: sig_alg,
            min_serial,
            max_serial,
        })
    }
}

fn der_parse_u64(reader: &mut untrusted::Reader<'_>) -> Result<u64, Error> {
    let value = nonnegative_integer(reader)?.as_slice_less_safe();
    der_value_slice_as_u64_be(value).ok_or(Error::ExtensionValueInvalid)
}

#[cfg(test)]
mod tests {
    use crate::mtc::ca::format::der_parse_u64;
    use crate::{Cert, Error};
    use alloc::boxed::Box;
    use x509_parser::asn1_rs::ToDer;

    #[test]
    fn test_parse_mtc_ca_subject_extract_cosigner_id() {
        // generated with the official MTC RFC demo, cert_10_3.pem
        //   ./demo generate
        //   openssl x509 -outform der -in ca_cert.pem -out ca-cert.der

        let cert_der = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/mtc/ca-cert.der"
        ));
        let cert = Cert::for_trust_anchor(untrusted::Input::from(cert_der)).unwrap();

        // test that this is the correct cert
        assert_eq!(cert.serial(), &[0x1]);

        assert_eq!(
            super::subject_extract_cosigner_id(cert.subject)
                .unwrap()
                .as_slice_less_safe(),
            x509_parser::asn1_rs::oid!(rel 32473.1).as_bytes()
        );
    }

    #[test]
    fn test_der_parse_u64() -> Result<(), Box<dyn core::error::Error>> {
        let values = [
            1,
            15,
            789,
            0,
            u64::MAX,
            1 << 8,
            (1 << 32) - 1,
            32419872453789,
        ];

        for value in values {
            let der_encoded = value.to_der_vec()?;
            let input = untrusted::Input::from(&der_encoded);
            input.read_all(Error::BadDer, |reader| {
                assert_eq!(value, der_parse_u64(reader)?);
                Ok(())
            })?;
        }

        Ok(())
    }
}
