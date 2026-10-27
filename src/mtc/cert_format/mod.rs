//! Types and helpers for the format of "regular" MTC certificates - section 6.2

use crate::mtc::cert_format::tls_vec::parse_vec_size_field;
use tls_parsing::{ParseError, TlsParse};
use tls_vec::{OpaqueVec, TlsVec};

pub(in crate::mtc) mod tls_parsing;
pub(in crate::mtc) mod tls_vec;

// constant sizes
const TRUST_ANCHOR_ID_MAX_LENGTH: usize = 255;
const COSIGNATURE_MAX_LENGTH: usize = (1 << 16) - 1;
const PROOF_EXTENSIONS_MAX_LENGTH: usize = (1 << 16) - 1;
const PROOF_INCLUSION_PROOF_MAX_SIZE: usize = (1 << 16) - 1;
const PROOF_SIGNATURES_MAX_LENGTH: usize = (1 << 24) - 1;

/// Binary representation of the trust anchor ID
pub(in crate::mtc) type TrustAnchorId<'a> = OpaqueVec<'a, 1, TRUST_ANCHOR_ID_MAX_LENGTH>;

/// MTC Cosignature
pub(in crate::mtc) struct Cosignature<'a> {
    pub(in crate::mtc) cosigner_id: TrustAnchorId<'a>,
    pub(in crate::mtc) signature: OpaqueVec<'a, 0, COSIGNATURE_MAX_LENGTH>,
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

// for comparisons
impl PartialEq for Cosignature<'_> {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(
            &self.cosigner_id.0.as_slice_less_safe(),
            &other.cosigner_id.0.as_slice_less_safe(),
        )
    }
}

impl PartialOrd for Cosignature<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        let slice1 = self.cosigner_id.0.as_slice_less_safe();
        let slice2 = other.cosigner_id.0.as_slice_less_safe();

        // compare length first
        match slice1.len().cmp(&slice2.len()) {
            // equal length: "Byte strings of the same length are ordered lexicographically"
            // --> rust slice comparisons are lexicographic
            core::cmp::Ordering::Equal => Some(slice1.cmp(slice2)),
            // longer or shorter --> simple
            ord => Some(ord),
        }
    }
}

/// Extension (section 5.2.1) in a TLS vector.
/// Completely unencoded, with its TLS vector size field also still stored.
pub(in crate::mtc) struct MtcLogEntryExtensions<'a> {
    pub(in crate::mtc) vec_header: untrusted::Input<'a>,
    pub(in crate::mtc) vec_data: untrusted::Input<'a>,
}

impl<'a> TlsParse<'a> for MtcLogEntryExtensions<'a> {
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError> {
        let (size, header) = parse_vec_size_field::<0, PROOF_EXTENSIONS_MAX_LENGTH>(reader)?;
        let raw_data = reader.read_bytes(size)?;
        Ok(Self {
            vec_header: header,
            vec_data: raw_data,
        })
    }
}

pub(in crate::mtc) struct MtcProof<'a> {
    pub(in crate::mtc) extensions: MtcLogEntryExtensions<'a>,
    // max. 48 bit
    pub(in crate::mtc) start: u64,
    // max. 48 bit
    pub(in crate::mtc) end: u64,
    pub(in crate::mtc) inclusion_proof: OpaqueVec<'a, 0, PROOF_INCLUSION_PROOF_MAX_SIZE>,
    pub(in crate::mtc) signatures: TlsVec<0, PROOF_SIGNATURES_MAX_LENGTH, Cosignature<'a>>,
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
        let extensions = MtcLogEntryExtensions::parse(reader)?;
        let start = parse_u48(reader)?;
        let end = parse_u48(reader)?;
        let inclusion_proof = OpaqueVec::parse(reader)?;

        let signatures = TlsVec::<_, _, Cosignature<'a>>::parse(reader)?;
        // verify signature sort order
        if !signatures.0.is_sorted() {
            return Err(ParseError::UnorderedCosignatures);
        }

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
    use crate::der::Tag;
    use crate::mtc::cert_format::MtcProof;
    use crate::mtc::cert_format::tls_parsing::{ParseError, TlsParse};
    use crate::{Cert, der};

    #[test]
    fn parse_signature() {
        // generated with the official MTC RFC demo, cert_10_3.pem
        //   ./demo generate
        //   openssl x509 -outform der -in cert_10_3.pem -out cert-standalone-simple.der
        let cert_der = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/mtc/cert-standalone-simple.der"
        ));
        let cert = Cert::from_der(untrusted::Input::from(cert_der)).unwrap();

        // test correct basic parsing
        assert_eq!(cert.serial(), &0x100000000000a_u64.to_be_bytes()[1..]);

        // test signature algorithm parsing
        let signature_algorithm = cert.signed_data.algorithm;
        let signature_algorithm = signature_algorithm
            .read_all(crate::Error::BadDer, |reader| {
                der::expect_tag(reader, Tag::OID)
            })
            .unwrap();
        assert_eq!(
            signature_algorithm.as_slice_less_safe(),
            pki_types::alg_id::MTC.as_ref()
        );

        // parse signature
        let signature = cert.signed_data.signature;
        let proof = signature
            .read_all(ParseError::IncompleteRead, MtcProof::parse)
            .unwrap();
        assert_eq!(proof.start, 8);
        assert_eq!(proof.end, 11);
        let signatures = proof.signatures.0;
        assert_eq!(signatures.len(), 1);
        let signature = &signatures[0];
        assert_eq!(
            signature.cosigner_id.0.as_slice_less_safe(),
            x509_parser::asn1_rs::oid!(rel 32473.1).as_bytes()
        );
    }
}
