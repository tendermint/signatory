use generic_array::GenericArray;

use super::Signer;
use curve::WeierstrassCurve;
use ecdsa::{DERSignature, FixedSignature};
use error::Error;

/// Sign a raw digest the same size as the curve's field (i.e. without first
/// computing a digest of the message)
pub trait RawDigestSigner<C>: Signer<C>
where
    C: WeierstrassCurve,
{
    /// Compute an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn sign_raw_digest_der(
        &self,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
    ) -> Result<DERSignature<C>, Error> {
        Ok(DERSignature::from(&self.sign_raw_digest_fixed(digest)?))
    }

    /// Compute a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn sign_raw_digest_fixed(
        &self,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
    ) -> Result<FixedSignature<C>, Error> {
        Ok(FixedSignature::from(&self.sign_raw_digest_der(digest)?))
    }
}
