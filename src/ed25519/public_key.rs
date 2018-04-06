//! Ed25519 public keys

use core::fmt;
use core::marker::PhantomData;

use error::{Error, ErrorKind};
use super::{DefaultVerifier, Signature, Verifier};
use util::fmt_colon_delimited_hex;

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public keys
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
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
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        if bytes.as_ref().len() != PUBLIC_KEY_SIZE {
            return Err(ErrorKind::KeyInvalid.into());
        }

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(bytes.as_ref());
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

impl<V: Verifier> AsRef<[u8]> for PublicKey<V> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<V: Verifier> fmt::Debug for PublicKey<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ed25519::PublicKey(")?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
