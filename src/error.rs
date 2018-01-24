//! Opaque error type

use core::fmt;

/// An opaque error type, used for all errors in Signatory
#[derive(Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::error::Error")
    }
}
