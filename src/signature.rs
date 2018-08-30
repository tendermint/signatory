use core::fmt::Debug;

use error::Error;
#[allow(unused_imports)]
use prelude::*;

/// Common trait for all signatures
pub trait Signature: AsRef<[u8]> + Debug + Sized {
    /// Create a signature from a serialized byte representation
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error>;

    /// Borrow a signature as a byte slice
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    /// Convert signature into owned byte array
    #[cfg(feature = "alloc")]
    #[inline]
    fn into_vec(self) -> Vec<u8> {
        self.as_slice().into()
    }
}
