//! Unified verifier API for all Signatory providers

use core::fmt::Debug;

pub(crate) mod bytes;
#[cfg(all(feature = "digest", feature = "generic-array"))]
pub(crate) mod digest;
pub(crate) mod sha2;

use error::Error;
use Signature;

#[cfg(all(feature = "digest", feature = "generic-array"))]
pub use self::digest::DigestVerifier;
pub use self::{bytes::ByteVerifier, sha2::Sha256Verifier};

/// Common trait for all signature verification providers
pub trait Verifier<I, S: Signature>: Debug + Send + Sync {
    /// Verify the signature against the given input (message or digest)
    /// using the public key this verifier was instantiated with.
    ///
    /// This trait should be implemented for the input type which is closest
    /// to the provider's own API.
    fn verify(&self, input: I, signature: &S) -> Result<(), Error>;
}
