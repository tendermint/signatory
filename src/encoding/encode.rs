use clear_on_drop::ClearOnDrop;
#[cfg(feature = "std")]
use std::{fs::File, io::Write, path::Path};
#[cfg(unix)]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

use super::{Encoding, FILE_MODE};
use error::Error;
use prelude::*;

/// Serialize keys/signatures with the given encoding (e.g. hex, Base64).
/// Uses constant time encoder/decoder implementations.
pub trait Encode: Sized {
    /// Encode `self` to a `Vec<u8>` using the provided `Encoding`, returning
    /// the encoded value or a `Error`.
    fn encode(&self, encoding: Encoding) -> Vec<u8>;

    /// Encode `self` to a `String` using the provided `Encoding`, returning
    /// the encoded value or a `Error`.
    ///
    /// Panics if the supplied encoding does not result in a UTF-8 string,
    /// i.e. `Encoding::Raw`
    fn encode_to_string<S: AsRef<str>>(&self, encoding: Encoding) -> String {
        String::from_utf8(self.encode(encoding)).unwrap()
    }

    /// Encode `self` with the given `Encoding`, writing the result to the
    /// supplied `io::Write` type, returning the number of bytes written or a `Error`.
    #[cfg(feature = "std")]
    fn encode_to_writer<W: Write>(
        &self,
        writer: &mut W,
        encoding: Encoding,
    ) -> Result<usize, Error> {
        let bytes = ClearOnDrop::new(self.encode(encoding));
        writer.write_all(bytes.as_ref())?;
        Ok(bytes.len())
    }

    /// Encode `self` and write it to a file at the given path, returning the
    /// resulting `File` or a `Error`.
    ///
    /// If the file does not exist, it will be created with a mode of
    /// `FILE_MODE` (i.e. `600`). If the file does exist, it will be erased
    /// and replaced.
    #[cfg(all(unix, feature = "std"))]
    fn encode_to_file<P: AsRef<Path>>(&self, path: P, encoding: Encoding) -> Result<File, Error> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(path)?;

        self.encode_to_writer(&mut file, encoding)?;
        Ok(file)
    }

    /// Encode `self` and write it to a file at the given path, returning the
    /// resulting `File` or a `Error`.
    ///
    /// If the file does not exist, it will be created.
    #[cfg(all(not(unix), feature = "std"))]
    fn encode_to_file<P: AsRef<Path>>(&self, path: P, encoding: Encoding) -> Result<File, Error> {
        let mut file = File::create(path.as_ref())?;
        self.encode_to_writer(&mut file, encoding)?;
        Ok(file)
    }
}
