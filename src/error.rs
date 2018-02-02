//! Error types

use failure::Context;

/// Error type
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    /// Obtain the ErrorKind for this Error
    pub fn kind(&self) -> ErrorKind {
        *self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { inner: kind.into() }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner }
    }
}

/// Kinds of errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Malformatted or otherwise invalid cryptographic key
    #[fail(display = "malformed or corrupt cryptographic key")]
    InvalidKey,

    /// Internal error within a cryptographic provider
    #[fail(display = "error inside cryptographic provider")]
    ProviderError,
}
