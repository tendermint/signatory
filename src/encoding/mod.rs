//! Support for encoding and decoding serialization formats (hex and Base64)
//! with implementations that do not branch on potentially secret data, such
//! as cryptographic keys.

#[macro_use]
mod macros;

#[cfg(feature = "ecdsa")]
pub(crate) mod asn1;
mod base64;
mod decode;
#[cfg(feature = "alloc")]
mod encode;
mod hex;
#[cfg(feature = "pkcs8")]
mod pkcs8;

pub use self::decode::Decode;
#[cfg(feature = "alloc")]
pub use self::encode::Encode;
#[cfg(feature = "pkcs8")]
pub use self::pkcs8::FromPkcs8;

use error::Error;
#[allow(unused_imports)]
use prelude::*;

/// Types of encodings natively supported by Signatory
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Encoding {
    /// Raw bytes
    Raw,

    /// Hexadecimal encoding
    Hex,

    /// Base64 (RFC 4648) encoding (no support for Base64uri, sorry)
    Base64,
}

/// Decode input bytes to output bytes
impl Encoding {
    /// Encode the input with this encoding into to the given buffer.
    /// Returns the size of the encoded output.
    ///
    /// Panics if the destination buffer is not sufficiently large to hold
    /// the encoded output.
    pub fn encode(self, src: &[u8], dst: &mut [u8]) -> usize {
        match self {
            Encoding::Raw => {
                dst.copy_from_slice(src);
                src.len()
            }
            Encoding::Hex => hex::encode(src, dst),
            Encoding::Base64 => base64::encode(src, dst),
        }
    }

    /// Encode the given raw bytes into a `Vec<u8>` of the given encoding
    #[cfg(feature = "alloc")]
    pub fn encode_vec<B: AsRef<[u8]>>(self, as_bytes: B) -> Vec<u8> {
        let bytes = as_bytes.as_ref();

        match self {
            Encoding::Raw => Vec::from(bytes),
            Encoding::Hex => {
                let mut output = vec![0u8; shl!(bytes.len(), 1)];
                let output_len = self.encode(bytes, &mut output);
                assert_eq!(output.len(), output_len);
                output
            }
            Encoding::Base64 => {
                let mut output = vec![0u8; mul!(add!(div!(bytes.len(), 3), 1), 4)];
                let output_len = self.encode(bytes, &mut output);
                output.truncate(output_len);
                output
            }
        }
    }

    /// Decode encoded bytes to the given destination buffer. Returns the size
    /// of the decoded output, or an error if decoding failed.
    ///
    /// Panics if the destination buffer is not sufficiently large given the
    /// input and encoding format.
    pub fn decode(self, src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        match self {
            Encoding::Raw => {
                dst.copy_from_slice(src);
                Ok(src.len())
            }
            Encoding::Hex => hex::decode(src, dst),
            Encoding::Base64 => base64::decode(src, dst),
        }
    }

    /// Decode the given encoded bytes into a `Vec<u8>`, or return an error if
    /// they failed to decode correctly
    #[cfg(feature = "alloc")]
    pub fn decode_vec<B: AsRef<[u8]>>(self, as_bytes: B) -> Result<Vec<u8>, Error> {
        let bytes = as_bytes.as_ref();

        match self {
            Encoding::Raw => Ok(Vec::from(bytes)),
            Encoding::Hex => {
                let mut output = vec![0u8; shr!(add!(bytes.len(), 1), 1)];
                // TODO: whitespace handling?
                let output_len = self.decode(bytes, &mut output)?;
                assert_eq!(output.len(), output_len);
                Ok(output)
            }
            Encoding::Base64 => {
                let mut output = vec![0u8; mul!(add!(div!(bytes.len(), 4), 1), 3)];
                // TODO: whitespace handling?
                let output_len = self.decode(bytes, &mut output)?;
                output.truncate(output_len);
                Ok(output)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_various_lengths() {
        let data = [b'X'; 64];

        for i in 0..data.len() {
            let encoded = Encoding::Base64.encode_vec(&data[..i]);

            // Make sure it round trips
            let decoded = Encoding::Base64.decode_vec(encoded).unwrap();

            assert_eq!(decoded.as_slice(), &data[..i]);
        }
    }

    #[test]
    fn hex_encode_various_lengths() {
        let data = [b'X'; 64];

        for i in 0..data.len() {
            let encoded = Encoding::Hex.encode_vec(&data[..i]);

            // Make sure it round trips
            let decoded = Encoding::Hex.decode_vec(encoded).unwrap();

            assert_eq!(decoded.as_slice(), &data[..i]);
        }
    }
}
