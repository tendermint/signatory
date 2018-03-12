//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

use error::Error;
use core::fmt;

/// curve25519-dalek software provider
#[cfg(feature = "dalek-provider")]
pub mod dalek;

/// `YubiHSM2` hardware provider
#[cfg(feature = "yubihsm-provider")]
pub mod yubihsm;

/// RFC 8032 Ed25519 test vectors
#[cfg(test)]
pub mod test_vectors;

#[cfg(feature = "dalek-provider")]
pub use self::dalek::DalekSigner;

#[cfg(feature = "yubihsm-provider")]
pub use self::yubihsm::YubiHSMSigner;

/// Size of an Ed25519 public key in bytes (256-bits)
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of an Ed25519 signature in bytes (512-bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 public keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    #[allow(dead_code)]
    pub(crate) fn new(bytes: &[u8]) -> Self {
        if bytes.len() != PUBLIC_KEY_SIZE {
            panic!("public key is incorrect size: {}", bytes.len())
        }

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(bytes);
        PublicKey(public_key)
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

/// Ed25519 signatures
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    #[allow(dead_code)]
    pub(crate) fn new(bytes: &[u8]) -> Self {
        if bytes.len() != SIGNATURE_SIZE {
            panic!("signature is incorrect size: {}", bytes.len())
        }

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(bytes);
        Signature(signature)
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

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ed25519::Signature(")?;

        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;

            if i != self.0.len() - 1 {
                write!(f, ":")?;
            }
        }

        write!(f, ")")
    }
}

/// Parent trait for Ed25519 signers
/// Signer is an object-safe trait for producing a particular type of signature
pub trait Signer {
    /// Compute an Ed25519 signature for the given message
    fn sign(&mut self, msg: &[u8]) -> Result<Signature, Error>;
}
