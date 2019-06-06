//! Support for encoding and decoding keys and signatures in hex or Base64.
//!
//! Uses a constant-time implementation which is suitable for use with
//! secret keys.

#[cfg(all(unix, feature = "std"))]
use super::FILE_MODE;
use crate::{prelude::*, Error};
#[cfg(feature = "std")]
use std::{fs::File, io::Write, path::Path};
#[cfg(all(unix, feature = "std"))]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
use subtle_encoding::Encoding;
#[cfg(feature = "std")]
use zeroize::Zeroize;

/// Serialize keys/signatures with the given encoding (e.g. hex, Base64).
/// Uses constant time encoder/decoder implementations.
pub trait Encode: Sized {
    /// Encode `self` to a `Vec<u8>` using the provided `Encoding`, returning
    /// the encoded value or a `Error`.
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8>;

    /// Encode `self` to a `String` using the provided `Encoding`, returning
    /// the encoded value or a `Error`.
    fn encode_to_string<E: Encoding>(&self, encoding: &E) -> Result<String, Error> {
        String::from_utf8(self.encode(encoding)).map_err(Error::from_cause)
    }

    /// Encode `self` with the given `Encoding`, writing the result to the
    /// supplied `io::Write` type, returning the number of bytes written or a `Error`.
    #[cfg(feature = "std")]
    fn encode_to_writer<W, E>(&self, writer: &mut W, encoding: &E) -> Result<usize, Error>
    where
        W: Write,
        E: Encoding,
    {
        let mut encoded_bytes = self.encode(encoding);
        writer
            .write_all(encoded_bytes.as_ref())
            .map_err(Error::from_cause)?;

        encoded_bytes.zeroize();
        Ok(encoded_bytes.len())
    }

    /// Encode `self` and write it to a file at the given path, returning the
    /// resulting `File` or a `Error`.
    ///
    /// If the file does not exist, it will be created with a mode of
    /// `FILE_MODE` (i.e. `600`). If the file does exist, it will be erased
    /// and replaced.
    #[cfg(all(unix, feature = "std"))]
    fn encode_to_file<P, E>(&self, path: P, encoding: &E) -> Result<File, Error>
    where
        P: AsRef<Path>,
        E: Encoding,
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(path)
            .map_err(Error::from_cause)?;

        self.encode_to_writer(&mut file, encoding)
            .map_err(Error::from_cause)?;

        Ok(file)
    }

    /// Encode `self` and write it to a file at the given path, returning the
    /// resulting `File` or a `Error`.
    ///
    /// If the file does not exist, it will be created.
    #[cfg(all(not(unix), feature = "std"))]
    fn encode_to_file<P, E>(&self, path: P, encoding: &E) -> Result<File, Error>
    where
        P: AsRef<Path>,
        E: Encoding,
    {
        let mut file = File::create(path.as_ref()).map_err(|e| Error::from_cause(e))?;

        self.encode_to_writer(&mut file, encoding)
            .map_err(Error::from_cause)?;

        Ok(file)
    }
}
