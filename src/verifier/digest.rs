//! Prehash (a.k.a. "IUF") verifying support using the `Digest` trait

use digest::{Digest, DigestOutput};

use error::Error;
use {Signature, Verifier};

/// A `Verifier` which takes a prehashed digest as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestVerifier<D: Digest, S: Signature> {
    /// Verify the output of the given `Digest` which was used to prehash a message
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error>;
}

impl<D, S, T> DigestVerifier<D, S> for T
where
    D: Digest,
    S: Signature,
    T: Verifier<DigestOutput<D>, S>,
{
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), Error> {
        self.verify(digest.fixed_result(), signature)
    }
}

/// Verify the given prehashed `Digest` with the given `Verifier`.
/// This can be used to avoid importing the `DigestVerifier` and `Signature` traits
pub fn verify_digest<D, S>(
    verifier: &DigestVerifier<D, S>,
    digest: D,
    signature: &S,
) -> Result<(), Error>
where
    D: Digest,
    S: Signature,
{
    verifier.verify_digest(digest, signature)
}
