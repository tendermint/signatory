//! ASN.1 DER-encoded ECDSA signatures

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::{fixed::FixedSignature, pair::IntPair, EcdsaSignature, EcdsaSignatureKind};
use curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;
use Signature;

/// ECDSA signatures encoded as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct Asn1Signature<C: WeierstrassCurve> {
    /// Signature data as bytes
    pub(super) bytes: GenericArray<u8, C::Asn1SignatureMaxSize>,

    /// Length of the signature in bytes (DER is variable-width)
    pub(super) length: usize,

    /// Placeholder for elliptic curve type
    pub(super) curve: PhantomData<C>,
}

impl<C> Signature for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Create an ASN.1 DER-encoded ECDSA signature from its serialized byte representation
    fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let length = bytes.as_ref().len();

        // TODO: better validate signature is well-formed ASN.1 DER
        ensure!(
            length <= C::Asn1SignatureMaxSize::to_usize(),
            SignatureInvalid,
            "max {}-byte signature (got {})",
            C::Asn1SignatureMaxSize::to_usize(),
            length
        );

        let mut array = GenericArray::default();
        array.as_mut_slice()[..length].copy_from_slice(bytes.as_ref());

        let result = Self {
            bytes: array,
            length,
            curve: PhantomData,
        };

        // Ensure result is well-formed ASN.1 DER
        IntPair::from_asn1_signature(&result)?;

        Ok(result)
    }
}

impl<C> EcdsaSignature for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    const SIGNATURE_KIND: EcdsaSignatureKind = EcdsaSignatureKind::Asn1;
}

impl<C> AsRef<[u8]> for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    fn as_ref(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }
}

impl<C> Debug for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::Asn1Signature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

impl<'s, C> From<&'s FixedSignature<C>> for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Parse `r` and `s` values from a fixed-width signature and reserialize
    /// them as ASN.1 DER.
    fn from(fixed_signature: &FixedSignature<C>) -> Self {
        IntPair::from_fixed_signature(fixed_signature).to_asn1_signature()
    }
}

impl<'s, C> From<&'s Asn1Signature<C>> for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn from(asn1_signature: &Asn1Signature<C>) -> FixedSignature<C> {
        // We always ensure `Asn1Signature`s parse successfully, so this should always work
        IntPair::from_asn1_signature(asn1_signature)
            .unwrap()
            .to_fixed_signature()
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use curve::nistp256::{Asn1Signature, FixedSignature, SHA256_FIXED_SIZE_TEST_VECTORS};
    use Signature;

    #[test]
    fn test_fixed_to_asn1_signature_roundtrip() {
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let fixed_signature = FixedSignature::from_bytes(&vector.sig).unwrap();

            // Convert to DER and back
            let asn1_signature = Asn1Signature::from(&fixed_signature);
            let fixed_signature2 = FixedSignature::from(&asn1_signature);

            assert_eq!(fixed_signature, fixed_signature2);
        }
    }
}
