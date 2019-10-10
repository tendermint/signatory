//! ASN.1 DER-encoded ECDSA signatures

#[cfg(feature = "encoding")]
use super::{fixed::FixedSignature, scalars::ScalarPair};
#[cfg(feature = "encoding")]
use crate::encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::encoding::Encode;
use crate::{
    ecdsa::{self, curve::WeierstrassCurve},
    util::fmt_colon_delimited_hex,
};
#[cfg(all(feature = "alloc", feature = "encoding"))]
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use generic_array::{typenum::Unsigned, GenericArray};
use signature::{Error, Signature};
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;

/// ECDSA signatures encoded as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct Asn1Signature<C: WeierstrassCurve> {
    /// Signature data as bytes
    pub(super) bytes: GenericArray<u8, C::Asn1SignatureMaxSize>,

    /// Length of the signature in bytes (DER is variable-width)
    pub(super) length: usize,
}

impl<C> Signature for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Decode an ASN.1 DER-serialized ECDSA signature
    fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let length = bytes.as_ref().len();

        // TODO: better validate signature is well-formed ASN.1 DER
        if length > C::Asn1SignatureMaxSize::to_usize() {
            return Err(Error::new());
        }

        let mut array = GenericArray::default();
        array.as_mut_slice()[..length].copy_from_slice(bytes.as_ref());

        let result = Self {
            bytes: array,
            length,
        };

        // Ensure result is well-formed ASN.1 DER
        #[cfg(feature = "encoding")]
        ScalarPair::from_asn1_signature(&result).ok_or_else(Error::new)?;

        Ok(result)
    }
}

impl<C: WeierstrassCurve> ecdsa::Signature for Asn1Signature<C> {}

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "signatory::ecdsa::Asn1Signature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

#[cfg(feature = "encoding")]
impl<C> Decode for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Decode an ASN.1 encoded ECDSA signature from a byte slice with the
    /// given encoding (e.g. hex, Base64)
    fn decode<E: Encoding>(
        encoded_signature: &[u8],
        encoding: &E,
    ) -> Result<Self, crate::encoding::Error> {
        let mut array = GenericArray::default();
        let decoded_len = encoding.decode_to_slice(encoded_signature, array.as_mut_slice())?;

        let result = Self {
            bytes: array,
            length: decoded_len,
        };

        // Ensure result is well-formed ASN.1 DER
        if ScalarPair::from_asn1_signature(&result).is_none() {
            Err(crate::encoding::error::ErrorKind::Decode)?;
        }

        Ok(result)
    }
}

#[cfg(all(feature = "alloc", feature = "encoding"))]
impl<C> Encode for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Encode an ASN.1 encoded ECDSA signature with the given encoding
    /// (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_ref())
    }
}

#[cfg(feature = "encoding")]
impl<'s, C> From<&'s FixedSignature<C>> for Asn1Signature<C>
where
    C: WeierstrassCurve,
{
    /// Parse `r` and `s` values from a fixed-width signature and reserialize
    /// them as ASN.1 DER.
    fn from(fixed_signature: &FixedSignature<C>) -> Self {
        ScalarPair::from_fixed_signature(fixed_signature).to_asn1_signature()
    }
}

#[cfg(feature = "encoding")]
impl<'s, C> From<&'s Asn1Signature<C>> for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn from(asn1_signature: &Asn1Signature<C>) -> FixedSignature<C> {
        // We always ensure `Asn1Signature`s parse successfully, so this should always work
        ScalarPair::from_asn1_signature(asn1_signature)
            .unwrap()
            .to_fixed_signature()
    }
}

#[cfg(all(test, feature = "encoding", feature = "test-vectors"))]
mod tests {
    use crate::ecdsa::curve::nistp256::{
        Asn1Signature, FixedSignature, SHA256_FIXED_SIZE_TEST_VECTORS,
    };
    use signature::Signature;

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
