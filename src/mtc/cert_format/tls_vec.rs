//! TLS presentation language (RFC 9846) vector types

use crate::mtc::cert_format::tls_parsing::{ParseError, TlsParse};
use alloc::vec::Vec;

fn parse_vec_size_field<const MIN_LENGTH: usize, const MAX_LENGTH: usize>(
    reader: &mut untrusted::Reader<'_>,
) -> Result<usize, ParseError> {
    let size_field_bits = MAX_LENGTH.bit_width();
    // The bit width is max. 64 --> 64 / 8 is max. 8 --> fits into usize on every Rust supported platform
    #[allow(clippy::as_conversions)]
    let size_field_bytes = size_field_bits.div_ceil(u8::BITS) as usize;

    // parse the size field
    let size_field = reader.read_bytes(size_field_bytes)?.as_slice_less_safe();

    // copy size field into fixed size buffer for interpretation as number
    let mut size_field_buffer = [0u8; size_of::<usize>()];
    let start_idx = size_field_buffer.len() - size_field.len();
    size_field_buffer[start_idx..].copy_from_slice(size_field);

    let size: usize = usize::from_be_bytes(size_field_buffer);

    // validate parsed size
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&size) {
        return Err(ParseError::InvalidVectorSize {
            min: MIN_LENGTH,
            max: MAX_LENGTH,
            is: size,
        });
    }

    Ok(size)
}

/// Representation of TLS (RFC9846) variable-sized vectors of opaque elements (3.4)
#[repr(transparent)]
#[cfg_attr(any(feature = "std", feature = "alloc", test), derive(Debug))]
pub(in crate::mtc) struct OpaqueVec<'a, const MIN_LENGTH: usize, const MAX_LENGTH: usize>(
    pub(in crate::mtc) untrusted::Input<'a>,
);

impl<'a, const MIN_LENGTH: usize, const MAX_LENGTH: usize> TlsParse<'a>
    for OpaqueVec<'a, MIN_LENGTH, MAX_LENGTH>
{
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError> {
        let size: usize = parse_vec_size_field::<MIN_LENGTH, MAX_LENGTH>(reader)?;

        // data does not need parsing
        let data = reader.read_bytes(size)?;

        Ok(Self(data))
    }
}

/// Representation of TLS (RFC9846) variable-sized vectors with a parsed type (3.4)
pub(in crate::mtc) struct TlsVec<const MIN_LENGTH: usize, const MAX_LENGTH: usize, T>(
    pub(in crate::mtc) Vec<T>,
);

impl<'a, const MIN_LENGTH: usize, const MAX_LENGTH: usize, T> TlsParse<'a>
    for TlsVec<MIN_LENGTH, MAX_LENGTH, T>
where
    T: TlsParse<'a>,
{
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError> {
        let size: usize = parse_vec_size_field::<MIN_LENGTH, MAX_LENGTH>(reader)?;

        let raw_data = reader.read_bytes(size)?;
        let data = raw_data.read_all(ParseError::IncompleteRead, |reader| {
            let mut data = Vec::new();
            while !reader.at_end() {
                data.push(T::parse(reader)?);
            }
            Ok(data)
        })?;

        Ok(Self(data))
    }
}

#[cfg(test)]
mod test {
    use super::OpaqueVec;
    use crate::mtc::cert_format::tls_parsing::{ParseError, TlsParse};
    use alloc::vec::Vec;
    use std::assert_matches;

    fn create_parsing_input(size_header: &[u8], data: &[u8]) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(size_header.len() + data.len());
        output.extend(size_header);
        output.extend(data);
        output
    }

    #[test]
    fn test_opaque_parsing_success() {
        const MAX_LENGTH: usize = 65535;

        // size is big endian encoded
        let test_cases = [
            // 8 elements
            ([0x0, 0x8], vec![1, 2, 3, 4, 5, 6, 7, 8]),
            // 16 elements
            (
                [0x0, 16],
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ),
            // 256 elements
            ([0x1, 0x0], vec![1; 256]),
        ];

        for (head, data) in test_cases {
            let input = create_parsing_input(&head, &data);
            let expected_output = data;

            let output = untrusted::Input::from(&input)
                .read_all(
                    ParseError::IncompleteRead,
                    OpaqueVec::<0, MAX_LENGTH>::parse,
                )
                .unwrap();

            assert_eq!(output.0.as_slice_less_safe(), expected_output.as_slice());
        }
    }

    #[test]
    fn test_opaque_parsing_fail() {
        const MAX_LENGTH: usize = 65536;

        // size is big endian encoded
        let test_cases: [(&[u8], Vec<u8>); _] = [
            // wrong header size
            (&[0x0, 0x8], vec![1, 2, 3, 4, 5, 6, 7, 8]),
            // too few elements
            (
                &[0x0, 0x0, 16],
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            ),
            // too many elements
            (&[0x0, 0x1, 0x0], vec![1; 389]),
        ];

        for (head, data) in test_cases {
            let input = create_parsing_input(head, &data);

            let output = untrusted::Input::from(&input).read_all(
                ParseError::IncompleteRead,
                OpaqueVec::<0, MAX_LENGTH>::parse,
            );

            assert_matches!(output, Err(_));
        }
    }
}
