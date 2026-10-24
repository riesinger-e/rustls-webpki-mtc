//! Types and helpers for the format of "regular" MTC certificates - section 6.2

use crate::mtc::tls_vec::{OpaqueVec, TlsVec};
use crate::mtc::{ParseError, TlsParse};
use der_parser::Oid;

/// OID of the MTC signature algorithm
pub(in crate::mtc) static OID_SIGNATURE_ALGORITHM: Oid<'static> =
    der_parser::oid!(1.3.6.1.5.5.7.6.67);

// constant sizes
const TRUST_ANCHOR_ID_MAX_LENGTH: usize = 255;
const COSIGNATURE_MAX_LENGTH: usize = (1 << 16) - 1;
const EXTENSION_MAX_DATA_SIZE: usize = (1 << 16) - 1;
const PROOF_EXTENSIONS_MAX_LENGTH: usize = (1 << 16) - 1;
const PROOF_INCLUSION_PROOF_MAX_SIZE: usize = (1 << 16) - 1;
const PROOF_SIGNATURES_MAX_LENGTH: usize = (1 << 24) - 1;

/// Binary representation of the trust anchor ID
pub(in crate::mtc) type TrustAnchorId<'a> = OpaqueVec<'a, 1, TRUST_ANCHOR_ID_MAX_LENGTH>;

/// MTC Cosignature
pub(in crate::mtc) struct Cosignature<'a> {
    cosigner_id: TrustAnchorId<'a>,
    signature: OpaqueVec<'a, 0, COSIGNATURE_MAX_LENGTH>,
}

impl<'a> TlsParse<'a> for Cosignature<'a> {
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError> {
        let trust_anchor_id = TrustAnchorId::parse(reader)?;
        let signature = OpaqueVec::<'a, 0, 65535>::parse(reader)?;

        Ok(Self {
            cosigner_id: trust_anchor_id,
            signature,
        })
    }
}

/// Enum with unknown values / section 5.2.1
#[repr(transparent)]
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
pub(in crate::mtc) struct MtcLogEntryExtensionType(u16);

impl TlsParse<'_> for MtcLogEntryExtensionType {
    fn parse(reader: &mut untrusted::Reader<'_>) -> Result<Self, ParseError> {
        let data = reader.read_bytes(size_of::<u16>())?;
        let data: &[u8; size_of::<u16>()] = data.as_slice_less_safe().as_array().expect(
            "Read size_of::<u16>() bytes --> Result should be an array of size_of::<u16> bytes",
        );

        let val = u16::from_be_bytes(*data);
        Ok(Self(val))
    }
}

/// Extension with payload / section 5.2.1
pub(in crate::mtc) struct MtcLogEntryExtension<'a> {
    extension_type: MtcLogEntryExtensionType,
    extension_data: OpaqueVec<'a, 0, EXTENSION_MAX_DATA_SIZE>,
}

impl<'a> TlsParse<'a> for MtcLogEntryExtension<'a> {
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError> {
        let typ = MtcLogEntryExtensionType::parse(reader)?;
        let data = OpaqueVec::parse(reader)?;
        Ok(Self {
            extension_type: typ,
            extension_data: data,
        })
    }
}

pub(in crate::mtc) struct MtcProof<'a> {
    extensions: TlsVec<0, PROOF_EXTENSIONS_MAX_LENGTH, MtcLogEntryExtension<'a>>,
    // max. 48 bit
    start: u64,
    // max. 48 bit
    end: u64,
    inclusion_proof: OpaqueVec<'a, 0, PROOF_INCLUSION_PROOF_MAX_SIZE>,
    signatures: TlsVec<0, PROOF_SIGNATURES_MAX_LENGTH, Cosignature<'a>>,
}

// parse a 48-bit TLS number
fn parse_u48(reader: &mut untrusted::Reader<'_>) -> Result<u64, ParseError> {
    // RFC 9846/section 3.3: numeric data types are constructed from a fixed length series of bytes, concatenated.

    // uint48 = 6 bytes
    const NUM_BYTES: usize = 6;

    let number_slice = reader.read_bytes(6)?;

    let mut number_buf: [u8; size_of::<u64>()] = [0; size_of::<u64>()];
    const START_IDX: usize = size_of::<u64>() - NUM_BYTES;
    number_buf[START_IDX..].copy_from_slice(number_slice.as_slice_less_safe());

    let number = u64::from_be_bytes(number_buf);
    Ok(number)
}

impl<'a> TlsParse<'a> for MtcProof<'a> {
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError>
    where
        Self: Sized,
    {
        let extensions = TlsVec::parse(reader)?;
        let start = parse_u48(reader)?;
        let end = parse_u48(reader)?;
        let inclusion_proof = OpaqueVec::parse(reader)?;
        let signatures = TlsVec::parse(reader)?;
        Ok(Self {
            extensions,
            start,
            end,
            inclusion_proof,
            signatures,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Cert;
    use crate::mtc::cert_format::MtcProof;
    use crate::mtc::{ParseError, TlsParse};

    #[test]
    fn parse_signature() {
        // generated with the official MTC RFC demo, cert_10_3.pem
        //   ./demo generate
        //   openssl x509 -outform der -in cert_10_3.pem -out cert-standalone-simple.der
        let cert_der = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/mtc/cert-standalone-simple.der"));
        let cert = Cert::from_der(untrusted::Input::from(cert_der)).unwrap();

        // test correct basic parsing
        assert_eq!(cert.serial(), &0x100000000000a_u64.to_be_bytes()[1..]);

        // test signature algorithm parsing
        let signature_algorithm = cert.signed_data.algorithm.as_slice_less_safe();
        let signature_algorithm = der_parser::parse_der(signature_algorithm).unwrap();
        let signature_algorithm = signature_algorithm.1.as_oid().unwrap();
        assert_eq!(signature_algorithm.as_bytes(), super::OID_SIGNATURE_ALGORITHM.as_bytes());

        // parse signature
        let signature = cert.signed_data.signature;
        let proof = signature.read_all(ParseError::IncompleteRead, MtcProof::parse).unwrap();
        assert!(proof.extensions.0.is_empty());
        assert_eq!(proof.start, 8);
        assert_eq!(proof.end, 11);
        let signatures = proof.signatures.0;
        assert_eq!(signatures.len(), 1);
        let signature = &signatures[0];
        assert_eq!(signature.cosigner_id.0.as_slice_less_safe(), der_parser::oid!(rel 32473.1).as_bytes());
    }
}