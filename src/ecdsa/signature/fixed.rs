//! Fixed-size, compact ECDSA signatures (as used in e.g. PKCS#11)

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::{EcdsaSignature, EcdsaSignatureKind};
use curve::WeierstrassCurve;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use encoding::Encode;
#[cfg(feature = "encoding")]
use encoding::{Decode, Encoding};
use error::Error;
#[allow(unused_imports)]
use prelude::*;
use util::fmt_colon_delimited_hex;
use Signature;

/// ECDSA signatures serialized in a compact, fixed-sized form
#[derive(Clone, PartialEq, Eq)]
pub struct FixedSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::FixedSignatureSize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C> Signature for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Create an ECDSA signature from its serialized byte representation
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        ensure!(
            bytes.as_ref().len() == C::FixedSignatureSize::to_usize(),
            SignatureInvalid,
            "expected {}-byte signature (got {})",
            C::FixedSignatureSize::to_usize(),
            bytes.as_ref().len()
        );

        Ok(Self::from(GenericArray::clone_from_slice(bytes.as_ref())))
    }
}

impl<C> EcdsaSignature for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    const SIGNATURE_KIND: EcdsaSignatureKind = EcdsaSignatureKind::Fixed;
}

impl<C> FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Convert signature into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::FixedSignatureSize> {
        self.bytes
    }
}

impl<C> AsRef<[u8]> for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl<C> Debug for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::FixedSignature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

#[cfg(feature = "encoding")]
impl<C> Decode for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Decode an ASN.1 encoded ECDSA signature from a byte slice with the
    /// given encoding (e.g. hex, Base64)
    fn decode(encoded_signature: &[u8], encoding: Encoding) -> Result<Self, Error> {
        let mut array = GenericArray::default();
        let decoded_len = encoding.decode(encoded_signature, array.as_mut_slice())?;

        ensure!(
            decoded_len == C::FixedSignatureSize::to_usize(),
            SignatureInvalid,
            "expected {}-byte signature (got {})",
            C::FixedSignatureSize::to_usize(),
            decoded_len
        );

        Ok(Self::from(array))
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl<C> Encode for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Encode an ASN.1 encoded ECDSA signature with the given encoding
    /// (e.g. hex, Base64)
    fn encode(&self, encoding: Encoding) -> Vec<u8> {
        encoding.encode_vec(self.as_ref())
    }
}

impl<C> From<GenericArray<u8, C::FixedSignatureSize>> for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn from(bytes: GenericArray<u8, C::FixedSignatureSize>) -> Self {
        Self {
            bytes,
            curve: PhantomData,
        }
    }
}
