use core::fmt::Debug;
#[cfg(all(feature = "digest", feature = "sha2"))]
use digest::Input;
use generic_array::typenum::U32;
#[cfg(feature = "sha2")]
use sha2::Sha256;

#[cfg(all(feature = "digest", feature = "sha2"))]
use super::DigestVerifier;
use curve::WeierstrassCurve;
use ecdsa::{Asn1Signature, FixedSignature, PublicKey};
use error::Error;

/// Verifier for ECDSA signatures which first hashes the input message using
/// the SHA-2 function whose digest matches the size of the elliptic curve's
/// field.
///
/// NOTE: Support is not (yet) provided for mixing and matching curve and
/// digest sizes. If you are interested in this, please open an issue.
pub trait Sha256Verifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve<ScalarSize = U32>,
{
    /// Verify an ASN.1 DER-encoded ECDSA signature for a given message using
    /// the given public key.
    fn verify_sha256_asn1_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &Asn1Signature<C>,
    ) -> Result<(), Error> {
        Self::verify_sha256_fixed_signature(key, msg, &FixedSignature::from(signature))
    }

    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature for a given message
    /// using the given public key.
    fn verify_sha256_fixed_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &FixedSignature<C>,
    ) -> Result<(), Error> {
        Self::verify_sha256_asn1_signature(key, msg, &Asn1Signature::from(signature))
    }
}

#[cfg(feature = "sha2")]
impl<C, V> Sha256Verifier<C> for V
where
    C: WeierstrassCurve<ScalarSize = U32>,
    V: DigestVerifier<C, Sha256>,
{
    fn verify_sha256_asn1_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &Asn1Signature<C>,
    ) -> Result<(), Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        Self::verify_digest_asn1_signature(key, sha256, signature)
    }

    fn verify_sha256_fixed_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &FixedSignature<C>,
    ) -> Result<(), Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        Self::verify_digest_fixed_signature(key, sha256, signature)
    }
}
