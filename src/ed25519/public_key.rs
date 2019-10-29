//! Ed25519 public keys

use core::fmt::{self, Debug};

#[cfg(feature = "encoding")]
use crate::encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::encoding::Encode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use alloc::vec::Vec;
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create an Ed25519 public key from a 32-byte array
    pub fn new(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        PublicKey(bytes)
    }

    /// Create an Ed25519 public key from its serialized (compressed Edwards-y) form
    pub fn from_bytes<B>(bytes: B) -> Option<Self>
    where
        B: AsRef<[u8]>,
    {
        if bytes.as_ref().len() == PUBLIC_KEY_SIZE {
            let mut public_key = [0u8; PUBLIC_KEY_SIZE];
            public_key.copy_from_slice(bytes.as_ref());
            Some(PublicKey(public_key))
        } else {
            None
        }
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ed25519::PublicKey({:?})", self.as_ref())
    }
}

#[cfg(feature = "encoding")]
impl Decode for PublicKey {
    /// Decode an Ed25519 public key from a byte slice with the given encoding
    /// (e.g. hex, Base64)
    fn decode<E: Encoding>(
        encoded_key: &[u8],
        encoding: &E,
    ) -> Result<Self, crate::encoding::Error> {
        let mut decoded_key = [0u8; PUBLIC_KEY_SIZE];
        let decoded_len = encoding.decode_to_slice(encoded_key, &mut decoded_key)?;

        if decoded_len == PUBLIC_KEY_SIZE {
            Ok(Self::new(decoded_key))
        } else {
            Err(crate::encoding::error::ErrorKind::Decode)?
        }
    }
}

#[cfg(all(feature = "alloc", feature = "encoding"))]
impl Encode for PublicKey {
    /// Encode an Ed25519 seed with the given encoding (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_bytes())
    }
}

impl crate::public_key::PublicKey for PublicKey {}
