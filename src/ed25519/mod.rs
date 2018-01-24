//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>

#[cfg(feature = "dalek")]
mod dalek;

#[cfg(test)]
pub mod test_vectors;

#[cfg(feature = "dalek")]
pub use self::dalek::DalekSigner;

/// Size of an Ed25519 signature (512-bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signatures
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Obtain signature as a byte slice
    pub fn to_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }

    /// Return signature as a raw byte slice
    pub fn into_bytes(self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Parent trait for Ed25519 signers
/// Signer is an object-safe trait for producing a particular type of signature
pub trait Signer {
    /// Compute an Ed25519 signature for the given message
    fn sign(&self, msg: &[u8]) -> Signature;
}
