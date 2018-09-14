//! Prehash (a.k.a. "IUF") signing support using the `Digest` trait

use digest::Digest;
use generic_array::ArrayLength;

use error::Error;
use {Signature, Signer};

/// Marker trait for `Signer` types which take a prehashed `Digest` as input.
/// The `digest` cargo feature must be enabled for this to be available.
pub trait DigestSigner<D, S>: Signer<D, S>
where
    D: Digest<OutputSize = Self::DigestSize>,
    S: Signature,
{
    /// Size of the digest output this verifier supports
    type DigestSize: ArrayLength<u8>;
}

/// Sign the given prehashed `Digest` with the given signer.
/// This can be used to avoid importing the `DigestSigner` and `Signature` traits
pub fn sign_digest<D, S>(
    signer: &DigestSigner<D, S, DigestSize = D::OutputSize>,
    digest: D,
) -> Result<S, Error>
where
    D: Digest,
    S: Signature,
{
    signer.sign(digest)
}
