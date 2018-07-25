//! Trait for ECDSA verifiers

use core::fmt::Debug;
use generic_array::{typenum::U32, GenericArray};
#[cfg(feature = "sha2")]
use sha2::{Digest, Sha256};

use super::{curve::WeierstrassCurve, DERSignature, FixedSignature, PublicKey};
use error::Error;

/// Verifier for ECDSA signatures which first hashes the input message using
/// the SHA-2 function whose digest matches the size of the elliptic curve's
/// field.
///
/// NOTE: Support is not (yet) provided for mixing and matching curve and
/// digest sizes. If you are interested in this, please open an issue.
pub trait SHA256DERVerifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    fn verify_sha256_der_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &DERSignature<C>,
    ) -> Result<(), Error>;
}

/// Verifier for ECDSA signatures which first hashes the input message using
/// the SHA-2 function whose digest matches the size of the elliptic curve's
/// field.
///
/// NOTE: Support is not (yet) provided for mixing and matching curve and
/// digest sizes. If you are interested in this, please open an issue.
pub trait SHA256FixedVerifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_sha256_fixed_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &FixedSignature<C>,
    ) -> Result<(), Error>;
}

/// Verify a raw message the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message)
pub trait RawDigestDERVerifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve,
{
    /// Verify an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn verify_digest_der_signature(
        key: &PublicKey<C>,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
        signature: &DERSignature<C>,
    ) -> Result<(), Error>;
}

/// Verify a raw message the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message)
pub trait RawDigestFixedVerifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve,
{
    /// Verify a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn verify_digest_fixed_signature(
        key: &PublicKey<C>,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
        signature: &FixedSignature<C>,
    ) -> Result<(), Error>;
}

#[cfg(feature = "sha2")]
impl<C, V> SHA256DERVerifier<C> for V
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
    V: RawDigestDERVerifier<C>,
{
    fn verify_sha256_der_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &DERSignature<C>,
    ) -> Result<(), Error> {
        Self::verify_digest_der_signature(key, &Sha256::digest(msg), signature)
    }
}

#[cfg(feature = "sha2")]
impl<C, V> SHA256FixedVerifier<C> for V
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
    V: RawDigestFixedVerifier<C>,
{
    fn verify_sha256_fixed_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &FixedSignature<C>,
    ) -> Result<(), Error> {
        Self::verify_digest_fixed_signature(key, &Sha256::digest(msg), signature)
    }
}
