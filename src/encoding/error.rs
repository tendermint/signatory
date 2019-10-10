//! Encoding errors

#[cfg(feature = "alloc")]
use alloc::{borrow::ToOwned, string::String};
use core::fmt::{self, Display};
#[cfg(feature = "std")]
use std::io;

/// Encoding error
#[derive(Clone, Debug)]
pub struct Error {
    /// Kind of error
    kind: ErrorKind,

    /// Optional message to associate with the error
    #[cfg(feature = "alloc")]
    msg: Option<String>,
}

impl Error {
    /// Create a new error of the given kind
    #[cfg_attr(not(feature = "alloc"), allow(unused_variables))]
    pub fn new(kind: ErrorKind, msg: Option<&str>) -> Self {
        Self {
            kind,
            #[cfg(feature = "alloc")]
            msg: msg.map(ToOwned::to_owned),
        }
    }

    /// Obtain the error's `ErrorKind`
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Get the message associated with this error (if available)
    #[cfg(feature = "alloc")]
    pub fn msg(&self) -> Option<&str> {
        self.msg.as_ref().map(AsRef::as_ref)
    }
}

impl Display for Error {
    #[cfg(not(feature = "alloc"))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind())
    }

    #[cfg(feature = "alloc")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{}: {}", self.kind(), msg)
        } else {
            write!(f, "{}", self.kind())
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error::new(kind, None)
    }
}

#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(_err: io::Error) -> Self {
        ErrorKind::Io.into()
    }
}

impl From<subtle_encoding::Error> for Error {
    fn from(_err: subtle_encoding::Error) -> Self {
        // TODO(tarcieri): preserve more error information here?
        ErrorKind::Encode.into()
    }
}

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    /// Decoding error
    Decode,

    /// Encoding error
    Encode,

    /// Input/output error
    Io,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ErrorKind::Decode => "decode error",
            ErrorKind::Encode => "encode error",
            ErrorKind::Io => "i/o error",
        };

        write!(f, "{}", msg)
    }
}
