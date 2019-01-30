//! Ed25519 signatures

use core::fmt::{self, Debug};
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;

#[cfg(feature = "encoding")]
use crate::encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::encoding::Encode;
use crate::error::Error;
#[allow(unused_imports)]
use crate::prelude::*;
use crate::signature::Signature as SignatureTrait;
use crate::util::fmt_colon_delimited_hex;

/// Size of an Ed25519 signature in bytes (512-bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signatures
#[derive(Clone)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create an Ed25519 signature from a 32-byte array
    pub fn new(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Signature(bytes)
    }

    /// Obtain signature as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Convert signature into owned byte array
    #[inline]
    pub fn into_bytes(self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ed25519::Signature(")?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

#[cfg(feature = "encoding")]
impl Decode for Signature {
    /// Decode an Ed25519 signature from a byte slice with the given encoding
    /// (e.g. hex, Base64)
    fn decode<E: Encoding>(encoded_signature: &[u8], encoding: &E) -> Result<Self, Error> {
        let mut decoded_signature = [0u8; SIGNATURE_SIZE];
        let decoded_len = encoding.decode_to_slice(encoded_signature, &mut decoded_signature)?;

        ensure!(
            decoded_len == SIGNATURE_SIZE,
            SignatureInvalid,
            "invalid {}-byte signature (expected {})",
            decoded_len,
            SIGNATURE_SIZE
        );

        Ok(Self::new(decoded_signature))
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl Encode for Signature {
    /// Encode an Ed25519 signature with the given encoding (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_ref())
    }
}

impl Eq for Signature {}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl SignatureTrait for Signature {
    /// Create an Ed25519 signature from its serialized byte representation
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        ensure!(
            bytes.as_ref().len() == SIGNATURE_SIZE,
            KeyInvalid,
            "expected {}-byte signature (got {})",
            SIGNATURE_SIZE,
            bytes.as_ref().len()
        );

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(bytes.as_ref());
        Ok(Signature(signature))
    }
}
