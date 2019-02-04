//! Prehash (a.k.a. "IUF") signing support using the `Digest` trait
//!
//! Enable Signatory's `digest` cargo feature to enable this trait.

use crate::{error::Error, Signature};
use digest::Digest;

/// Trait for signers which take a prehashed `Digest` as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestSigner<D, S>: Send + Sync
where
    D: Digest,
    S: Signature,
{
    /// Sign the output of the given digest with signer's private key,
    /// returning a signature.
    fn sign(&self, digest: D) -> Result<S, Error>;
}

/// Sign the given prehashed `Digest` with the given signer.
/// This can be used to avoid importing the `DigestSigner` and `Signature` traits
pub fn sign_digest<D, S>(signer: &DigestSigner<D, S>, digest: D) -> Result<S, Error>
where
    D: Digest,
    S: Signature,
{
    signer.sign(digest)
}
