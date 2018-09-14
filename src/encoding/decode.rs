#[cfg(feature = "std")]
use clear_on_drop::ClearOnDrop;
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

use super::Encoding;
use error::Error;

/// Decode objects from encoded data (e.g. hex, Base64). Uses constant time
/// encoder/decoder implementations designed to avoid leaking private keys.
pub trait Decode: Sized {
    /// Decode the given byte slice using the provided `Encoding`, returning
    /// the decoded value or a `Error`.
    fn decode(encoded: &[u8], encoding: Encoding) -> Result<Self, Error>;

    /// Decode the given string-alike type with the provided `Encoding`,
    /// returning the decoded value or a `Error`.
    fn decode_from_str<S: AsRef<str>>(encoded: S, encoding: Encoding) -> Result<Self, Error> {
        Self::decode(encoded.as_ref().as_bytes(), encoding)
    }

    /// Decode the data read from the given `io::Read` type with the provided
    /// `Encoding`, returning the decoded value or a `Error`.
    #[cfg(feature = "std")]
    fn decode_from_reader<R: Read>(reader: &mut R, encoding: Encoding) -> Result<Self, Error> {
        let mut bytes = ClearOnDrop::new(vec![]);
        reader.read_to_end(bytes.as_mut())?;
        Self::decode(&bytes, encoding)
    }

    /// Read a file at the given path, decoding the data it contains using
    /// the provided `Encoding`, returning the decoded value or a `Error`.
    #[cfg(feature = "std")]
    fn decode_from_file<P: AsRef<Path>>(path: P, encoding: Encoding) -> Result<Self, Error> {
        Self::decode_from_reader(&mut File::open(path.as_ref())?, encoding)
    }
}
