//! Ed25519 signatures

use core::fmt;

use error::Error;
use util::fmt_colon_delimited_hex;

/// Size of an Ed25519 signature in bytes (512-bits)
pub const SIGNATURE_SIZE: usize = 64;

/// Ed25519 signatures
#[derive(Clone)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create an Ed25519 signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
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
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

impl Eq for Signature {}
