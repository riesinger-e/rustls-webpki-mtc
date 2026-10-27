//! TLS (RFC 9846) parsing to read the cert data

use core::error::Error;
use core::fmt::Display;

/// TLS (RFC 9846) Parsing Error
#[derive(Debug)]
pub(in crate::mtc) enum ParseError {
    EndOfInput,
    InvalidVectorSize { min: usize, max: usize, is: usize },
    IncompleteRead,
    UnorderedCosignatures,
}

impl Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EndOfInput => write!(f, "end of input"),
            Self::InvalidVectorSize { min, max, is } => write!(
                f,
                "invalid TLS vector size. Expected {min} <= size <= {max}, is: {is}"
            ),
            Self::IncompleteRead => write!(f, "incomplete read, left over bytes"),
            Self::UnorderedCosignatures => write!(f, "The MTC cosignatures are not ordered"),
        }
    }
}

impl Error for ParseError {}

impl From<untrusted::EndOfInput> for ParseError {
    fn from(_: untrusted::EndOfInput) -> Self {
        Self::EndOfInput
    }
}

/// Parse a type from it's TLS (RFC 9846) representation
pub(in crate::mtc) trait TlsParse<'a> {
    /// Parse from an untrusted byte stream
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError>
    where
        Self: Sized;
}
