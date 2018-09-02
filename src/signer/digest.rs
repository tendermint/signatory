//! Prehash (a.k.a. "IUF") signing support using the `Digest` trait

use digest::{Digest, DigestOutput};

use error::Error;
use {Signature, Signer};

/// A signer which takes a prehashed digest as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestSigner<D: Digest, S: Signature> {
    /// Sign the output of the given `Digest` which was used to prehash a message
    fn sign_digest(&self, digest: D) -> Result<S, Error>;
}

impl<D, S, T> DigestSigner<D, S> for T
where
    D: Digest,
    S: Signature,
    T: Signer<DigestOutput<D>, S>,
{
    fn sign_digest(&self, digest: D) -> Result<S, Error> {
        self.sign(digest.fixed_result())
    }
}

/// Sign the given prehashed `Digest` with the given signer.
/// This can be used to avoid importing the `DigestSigner` and `Signature` traits
pub fn sign_digest<D, S>(signer: &DigestSigner<D, S>, digest: D) -> Result<S, Error>
where
    D: Digest,
    S: Signature,
{
    signer.sign_digest(digest)
}
