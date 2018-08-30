//! Support for the `PKCS#8` private key format described in [RFC 5208] and [RFC 5915]
//!
//! [RFC 5208]: https://tools.ietf.org/html/rfc5208
//! [RFC 5915]: https://tools.ietf.org/html/rfc5915

#[cfg(feature = "std")]
use clear_on_drop::clear::Clear;
use error::Error;
#[cfg(feature = "std")]
use std::{fs::File, io::Read, path::Path};

/// Instantiate this type from a `PKCS#8` private key
pub trait FromPkcs8: Sized {
    /// Load the given `PKCS#8`-encoded private key, returning `Self` or an
    /// error if the given data couldn't be loaded
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error>;

    /// Read `PKCS#8` data from the given `std::io::Read`
    #[cfg(feature = "std")]
    fn read_pkcs8<R: Read>(mut reader: R) -> Result<Self, Error> {
        let mut bytes = vec![];
        reader
            .read_to_end(&mut bytes)
            .map_err(|e| err!(KeyInvalid, "error reading key: {}", e))?;
        let result = Self::from_pkcs8(&bytes);
        bytes.as_mut_slice().clear();
        result
    }

    /// Read `PKCS#8` data from the file at the given path
    #[cfg(feature = "std")]
    fn from_pkcs8_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Self::read_pkcs8(File::open(path)?)
    }
}
