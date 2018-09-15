//! Impls of `DigestSigner` and `DigestVerifier` for all Ed25519 signers and
//! verifiers which accept 512-bit digest inputs.
//!
//! In practice the digest algorithm will always be SHA-512, but we allow for
//! multiple implementations which conform to the `Digest` API (as opposed to
//! only doing an impl for `sha2::Sha512`).

use super::Ed25519Signature;
use digest::{generic_array::typenum::U64, Digest};
use signer::{DigestSigner, Signer};
use verifier::{DigestVerifier, Verifier};

impl<D, T> DigestSigner<D, Ed25519Signature> for T
where
    D: Digest<OutputSize = U64>,
    T: Signer<D, Ed25519Signature>,
{
    type DigestSize = U64;
}

impl<D, T> DigestVerifier<D, Ed25519Signature> for T
where
    D: Digest<OutputSize = U64>,
    T: Verifier<D, Ed25519Signature>,
{
    type DigestSize = U64;
}
