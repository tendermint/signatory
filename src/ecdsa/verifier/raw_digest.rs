use core::fmt::Debug;
use generic_array::GenericArray;

use curve::WeierstrassCurve;
use ecdsa::{Asn1Signature, FixedSignature, PublicKey};
use error::Error;

/// Verify a raw message the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message)
pub trait RawDigestVerifier<C>: Clone + Debug + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve,
{
    /// Verify an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn verify_raw_digest_asn1_signature(
        key: &PublicKey<C>,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
        signature: &Asn1Signature<C>,
    ) -> Result<(), Error> {
        Self::verify_raw_digest_fixed_signature(key, digest, &FixedSignature::from(signature))
    }

    /// Verify a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn verify_raw_digest_fixed_signature(
        key: &PublicKey<C>,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
        signature: &FixedSignature<C>,
    ) -> Result<(), Error> {
        Self::verify_raw_digest_asn1_signature(key, digest, &Asn1Signature::from(signature))
    }
}
