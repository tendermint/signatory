//! Ed25519 public keys

use core::fmt;

#[cfg(
    any(
        feature = "dalek-provider",
        feature = "ring-provider",
        feature = "sodiumoxide-provider"
    )
)]
use super::{DefaultVerifier, Signature, Verifier};
use error::Error;
use util::fmt_colon_delimited_hex;

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Create an Ed25519 public key from its serialized (compressed Edwards-y) form
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            bytes.as_ref().len() == PUBLIC_KEY_SIZE,
            KeyInvalid,
            "expected {}-byte key (got {})",
            PUBLIC_KEY_SIZE,
            bytes.as_ref().len()
        );

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(bytes.as_ref());
        Ok(PublicKey(public_key))
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

    /// Verify a signature using this key
    #[cfg(
        any(
            feature = "dalek-provider",
            feature = "ring-provider",
            feature = "sodiumoxide-provider"
        )
    )]
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        DefaultVerifier::verify(self, msg, signature)
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ed25519::PublicKey(")?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
