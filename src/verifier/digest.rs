//! Prehash (a.k.a. "IUF") verifying support using the `Digest` trait

use digest::Digest;
use generic_array::ArrayLength;

use error::Error;
use {Signature, Verifier};

/// Marker trait for `Verifier` types which take a prehashed `Digest` as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestVerifier<D, S>: Verifier<D, S>
where
    D: Digest<OutputSize = Self::DigestSize>,
    S: Signature,
{
    /// Size of the digest output this verifier supports
    type DigestSize: ArrayLength<u8>;
}

/// Verify the given prehashed `Digest` with the given `Verifier`.
/// This can be used to avoid importing the `DigestVerifier` and `Signature` traits
pub fn verify_digest<D, L, S>(
    verifier: &DigestVerifier<D, S, DigestSize = D::OutputSize>,
    digest: D,
    signature: &S,
) -> Result<(), Error>
where
    D: Digest,
    S: Signature,
{
    verifier.verify(digest, signature)
}
