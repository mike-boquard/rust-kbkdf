//! Errors for KBKDF crate

use std::fmt::Formatter;

/// Errors returned by the KBKDF function
#[derive(Debug)]
pub enum Error {
    /// Derived key length is invalid
    InvalidDerivedKeyLen,
    /// Provided buffer is of invalid size
    InvalidBufferLength(String),
    /// Error with implementation
    ImplementationError(String),
    /// Invalid key size
    InvalidKeySize(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDerivedKeyLen => write!(f, "Derived key length is invalid"),
            Error::InvalidBufferLength(e) => write!(f, "Invalid output buffer provided: {}", e),
            Error::ImplementationError(e) => write!(f, "{}", e),
            Error::InvalidKeySize(e) => write!(f, "Invalid key size provided: {}", e),
        }
    }
}

impl std::error::Error for Error {}
