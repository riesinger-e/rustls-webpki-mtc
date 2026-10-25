//! Types and helpers for the format of MTC CA certificates, section 5.5

use crate::der;
use crate::mtc::ParseError;
use der_parser::Oid;

pub(crate) fn mtc_ca_subject_extract_cosigner_id(
    subject: untrusted::Input<'_>,
) -> Result<untrusted::Input<'_>, ParseError> {
    /// Identifies a subject containing a CA (cosigner) ID
    static MTC_CA_OID: Oid<'static> = der_parser::oid!(1.3.6.1.5.5.7.25.3);

    // parse the subject as a PKIX distinguished Name (section 5.1)
    let (oid, cosigner_id) = subject
        .read_all(crate::Error::BadDer, |reader| {
            der::nested(reader, der::Tag::Set, crate::Error::BadDer, |reader| {
                der::nested(reader, der::Tag::Sequence, crate::Error::BadDer, |reader| {
                    let oid = der::expect_tag(reader, der::Tag::OID)?;
                    let cosigner_id = der::expect_tag(reader, der::Tag::RelativeOID)?;

                    Ok((oid, cosigner_id))
                })
            })
        })
        .map_err(|_| ParseError::MalformedCa)?;

    if oid.as_slice_less_safe() != MTC_CA_OID.as_bytes() {
        // wrong attribute type
        return Err(ParseError::MalformedCa);
    }

    Ok(cosigner_id)
}

#[cfg(test)]
mod tests {
    use crate::Cert;

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
            super::mtc_ca_subject_extract_cosigner_id(cert.subject)
                .unwrap()
                .as_slice_less_safe(),
            der_parser::oid!(rel 32473.1).as_bytes()
        );
    }
}
