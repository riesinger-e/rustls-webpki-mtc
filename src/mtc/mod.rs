#![cfg(feature = "mtc")]

use core::error::Error;
use core::fmt::Display;

mod ca_format;
mod cert_format;
mod tls_vec;

// TLS (RFC 9846) parsing to read the cert data

/// TLS (RFC 9846) Parsing Error
#[derive(Debug)]
enum ParseError {
    EndOfInput,
    InvalidVectorSize { min: usize, max: usize, is: usize },
    IncompleteRead,
    MalformedCa,
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
            Self::MalformedCa => write!(f, "Certificate does not seem to be an MTC CA certificate"),
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
trait TlsParse<'a> {
    /// Parse from an untrusted byte stream
    fn parse(reader: &mut untrusted::Reader<'a>) -> Result<Self, ParseError>
    where
        Self: Sized;
}
