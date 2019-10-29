//! Raw ECDSA secret keys: `x` value for ECDSA.

#[cfg(feature = "encoding")]
use crate::encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::encoding::Encode;
use ::ecdsa::{
    generic_array::{typenum::Unsigned, GenericArray},
    Curve,
};
#[cfg(all(feature = "alloc", feature = "encoding"))]
use alloc::vec::Vec;
#[cfg(feature = "getrandom")]
use getrandom::getrandom;
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;
use zeroize::Zeroize;

/// Raw ECDSA secret keys: raw scalar value `Curve::ScalarBytes`
/// in size used as the `x` value for ECDSA.
pub struct SecretKey<C: Curve> {
    /// Byte serialization of a secret scalar for ECDSA
    bytes: GenericArray<u8, C::ScalarSize>,
}

impl<C: Curve> SecretKey<C> {
    /// Create a raw ECDSA secret key
    pub fn new(into_bytes: impl Into<GenericArray<u8, C::ScalarSize>>) -> Self {
        Self {
            bytes: into_bytes.into(),
        }
    }

    /// Decode a raw ECDSA secret key from the given byte slice
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Option<Self> {
        let slice = bytes.as_ref();
        let length = slice.len();

        if length == C::ScalarSize::to_usize() {
            Some(Self::new(GenericArray::clone_from_slice(slice)))
        } else {
            None
        }
    }

    /// Generate a new ECDSA secret key using the operating system's
    /// cryptographically secure random number generator
    #[cfg(feature = "getrandom")]
    pub fn generate() -> Self {
        let mut bytes = GenericArray::default();
        getrandom(bytes.as_mut_slice()).expect("RNG failure!");
        Self { bytes }
    }

    /// Expose this `SecretKey` as a byte slice
    pub fn as_secret_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: Curve> Clone for SecretKey<C> {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

#[cfg(feature = "encoding")]
impl<C: Curve> Decode for SecretKey<C> {
    /// Decode an Ed25519 seed from a byte slice with the given encoding (e.g. hex, Base64)
    fn decode<E: Encoding>(
        encoded_key: &[u8],
        encoding: &E,
    ) -> Result<Self, crate::encoding::Error> {
        let mut bytes = GenericArray::default();
        let decoded_len = encoding.decode_to_slice(encoded_key, &mut bytes)?;

        if decoded_len == C::ScalarSize::to_usize() {
            Ok(Self { bytes })
        } else {
            Err(crate::encoding::error::ErrorKind::Decode.into())
        }
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl<C: Curve> Encode for SecretKey<C> {
    /// Encode an Ed25519 seed with the given encoding (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_secret_slice())
    }
}

impl<C: Curve> Drop for SecretKey<C> {
    fn drop(&mut self) {
        self.bytes.as_mut().zeroize();
    }
}
