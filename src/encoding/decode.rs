#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};
use subtle_encoding::Encoding;
#[cfg(feature = "std")]
use zeroize::secure_zero_memory;

use error::Error;

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
        secure_zero_memory(&mut bytes);
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
        Self::decode_from_reader(&mut File::open(path.as_ref())?, encoding)
    }
}
