//! Ed25519 signatures

use core::fmt;

use error::{Error, ErrorKind};

/// Size of an Ed25519 signature in bytes (512-bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signatures
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create an Ed25519 signature from its serialized byte representation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(ErrorKind::SignatureInvalid.into());
        }

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(bytes);
        Ok(Signature(signature))
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
