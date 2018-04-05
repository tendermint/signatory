//! Ed25519 public keys

use core::marker::PhantomData;

use error::Error;
use super::{DefaultVerifier, Signature, Verifier};

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey<V = DefaultVerifier>
where
    V: Verifier,
{
    /// Compressed Edwards-y coordinate representing an Ed25519 public key
    pub bytes: [u8; PUBLIC_KEY_SIZE],

    /// Placeholder for verification provider
    verifier: PhantomData<V>,
}

impl<V: Verifier> PublicKey<V> {
    /// Create an Ed25519 public key from its serialized (compressed Edwards-y) form
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            panic!("public key is incorrect size: {}", bytes.len())
        }

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(bytes);
        Ok(Self {
            bytes: public_key,
            verifier: PhantomData,
        })
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Verify a signature using this key
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        V::verify(self, msg, signature)
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
