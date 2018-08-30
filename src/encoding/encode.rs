use clear_on_drop::ClearOnDrop;
#[cfg(feature = "std")]
use std::{fs::File, io::Write, path::Path};

use super::Encoding;
use error::Error;
use prelude::*;

/// Encode objects from bytes data (e.g. hex, Base64). Uses constant time
/// encoder/encoder implementations designed to avoid leaking private keys.
pub trait Encode: Sized {
    /// Encode this object to a `Vec<u8>` using the provided `Encoding`, returning
    /// the encoded value or a `Error`.
    fn encode(&self, encoding: Encoding) -> Vec<u8>;

    /// Encode the given string-alike type with the provided `Encoding`,
    /// returning the encoded value or a `Error`.
    ///
    /// Panics if the supplied encoding does not result in a UTF-8 string,
    /// i.e. `Encoding::Raw`
    fn encode_to_string<S: AsRef<str>>(&self, encoding: Encoding) -> String {
        String::from_utf8(self.encode(encoding)).unwrap()
    }

    /// Encode the data read to the given `io::Read` type with the provided
    /// `Encoding`, returning the encoded value or a `Error`.
    #[cfg(feature = "std")]
    fn encode_to_writer<W: Write>(
        &self,
        writer: &mut W,
        encoding: Encoding,
    ) -> Result<usize, Error> {
        let bytes = ClearOnDrop::new(self.encode(encoding));
        Ok(writer.write(bytes.as_ref())?)
    }

    /// Read a file at the given path, decoding the data it contains using
    /// the provided `Encoding`, returning the encoded value or a `Error`.
    #[cfg(feature = "std")]
    fn encode_to_file<P: AsRef<Path>>(&self, path: P, encoding: Encoding) -> Result<File, Error> {
        let mut file = File::open(path.as_ref())?;
        self.encode_to_writer(&mut file, encoding)?;
        Ok(file)
    }
}
