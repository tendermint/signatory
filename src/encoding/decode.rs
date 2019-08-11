//! Support for decoding keys and signatures in hex or Base64.
//!
//! Uses a constant-time implementation which is suitable for use with
//! secret keys.

use super::error::Error;
#[cfg(feature = "std")]
use super::error::ErrorKind;
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};
use subtle_encoding::Encoding;
#[cfg(feature = "std")]
use zeroize::Zeroize;

/// Decode keys/signatures from encoded data (e.g. hex, Base64).
/// Uses constant time encoder/decoder implementations.
pub trait Decode: Sized {
    /// Decode the given byte slice using the provided `Encoding`, returning
    /// the decoded value or a `Error`.
    fn decode<E: Encoding>(encoded: &[u8], encoding: &E) -> Result<Self, Error>;

    /// Decode the given string-alike type with the provided `Encoding`,
    /// returning the decoded value or a `Error`.
    fn decode_from_str<S, E>(encoded_str: S, encoding: &E) -> Result<Self, Error>
    where
        S: AsRef<str>,
        E: Encoding,
    {
        Self::decode(encoded_str.as_ref().as_bytes(), encoding)
    }

    /// Decode the data read from the given `io::Read` type with the provided
    /// `Encoding`, returning the decoded value or a `Error`.
    #[cfg(feature = "std")]
    fn decode_from_reader<R, E>(reader: &mut R, encoding: &E) -> Result<Self, Error>
    where
        R: Read,
        E: Encoding,
    {
        let mut bytes = vec![];
        reader.read_to_end(bytes.as_mut())?;

        let result = Self::decode(&bytes, encoding);
        bytes.zeroize();
        result
    }

    /// Read a file at the given path, decoding the data it contains using
    /// the provided `Encoding`, returning the decoded value or a `Error`.
    #[cfg(feature = "std")]
    fn decode_from_file<P, E>(path: P, encoding: &E) -> Result<Self, Error>
    where
        P: AsRef<Path>,
        E: Encoding,
    {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|e| {
            Error::new(
                ErrorKind::Io,
                Some(&format!("couldn't open {}: {}", path.display(), e)),
            )
        })?;

        Self::decode_from_reader(&mut file, encoding)
    }
}
