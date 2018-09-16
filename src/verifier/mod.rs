//! Unified verifier API for all Signatory providers

use core::fmt::Debug;

pub(crate) mod bytes;
#[cfg(feature = "digest")]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(feature = "digest")]
pub use self::digest::*;
pub use self::{bytes::*, sha2::*};

/// Common trait for all signature verification providers
pub trait Verifier<I, S: Signature>: Debug + Send + Sync {
    /// Verify the signature against the given input (message or digest)
    /// using the public key this verifier was instantiated with.
    ///
    /// This trait should be implemented for the input type which is closest
    /// to the provider's own API.
    fn verify(&self, input: I, signature: &S) -> Result<(), Error>;
}
