use digest::Digest;

use super::{RawDigestSigner, Signer};
use curve::WeierstrassCurve;
use ecdsa::{DERSignature, FixedSignature};
use error::Error;

/// Compute the signature of the given `digest::Digest`, whose output size
/// must be equal to the modulus of the curve.
pub trait DigestSigner<C, D>: Signer<C>
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::PrivateScalarSize> + Default,
{
    /// Compute an ASN.1 DER-encoded ECDSA signature for the given `Digest`
    fn sign_digest_der(&self, digest: D) -> Result<DERSignature<C>, Error> {
        Ok(DERSignature::from(&self.sign_digest_fixed(digest)?))
    }

    /// Compute a compact, fixed-width ECDSA signature for the given `Digest`
    fn sign_digest_fixed(&self, digest: D) -> Result<FixedSignature<C>, Error> {
        Ok(FixedSignature::from(&self.sign_digest_der(digest)?))
    }
}

impl<C, D, S> DigestSigner<C, D> for S
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::PrivateScalarSize> + Default,
    S: RawDigestSigner<C>,
{
    fn sign_digest_der(&self, digest: D) -> Result<DERSignature<C>, Error> {
        self.sign_raw_digest_der(&digest.fixed_result())
    }

    fn sign_digest_fixed(&self, digest: D) -> Result<FixedSignature<C>, Error> {
        self.sign_raw_digest_fixed(&digest.fixed_result())
    }
}
