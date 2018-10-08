//! Prehash (a.k.a. "IUF") verifying support using the `Digest` trait.
//!
//! Enable Signatory's `digest` cargo feature to enable this trait.

use digest::Digest;

use error::Error;
use Signature;

/// Trait for verifiers which take a prehashed `Digest` as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestVerifier<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Verify the signature against the output of the given `Digest`
    /// using the public key this verifier was instantiated with.
    fn verify(&self, digest: D, signature: &S) -> Result<(), Error>;
}

/// Verify the given prehashed `Digest` with the given `Verifier`.
/// This can be used to avoid importing the `DigestVerifier` and `Signature` traits
pub fn verify_digest<D, L, S>(
    verifier: &DigestVerifier<D, S>,
    digest: D,
    signature: &S,
) -> Result<(), Error>
where
    D: Digest,
    S: Signature,
{
    verifier.verify(digest, signature)
}
