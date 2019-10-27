//! Fixed-size, compact ECDSA signatures (as used in e.g. PKCS#11)

#[cfg(feature = "encoding")]
use crate::encoding::Decode;
#[cfg(all(feature = "alloc", feature = "encoding"))]
use crate::encoding::Encode;
use crate::{
    ecdsa::{self, curve::WeierstrassCurve},
    util::fmt_colon_delimited_hex,
};
#[cfg(all(feature = "encoding", feature = "alloc"))]
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use generic_array::{typenum::Unsigned, GenericArray};
use signature::{Error, Signature};
#[cfg(feature = "encoding")]
use subtle_encoding::Encoding;

/// ECDSA signatures serialized in a compact, fixed-sized form
#[derive(Clone, PartialEq, Eq)]
pub struct FixedSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::FixedSignatureSize>,
}

impl<C> Signature for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Create an ECDSA signature from its serialized byte representation
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        if bytes.as_ref().len() == C::FixedSignatureSize::to_usize() {
            Ok(Self::from(GenericArray::clone_from_slice(bytes.as_ref())))
        } else {
            Err(Error::new())
        }
    }
}

impl<C: WeierstrassCurve> ecdsa::Signature for FixedSignature<C> {}

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn decode<E: Encoding>(
        encoded_signature: &[u8],
        encoding: &E,
    ) -> Result<Self, crate::encoding::Error> {
        let mut array = GenericArray::default();
        let decoded_len = encoding.decode_to_slice(encoded_signature, array.as_mut_slice())?;

        if decoded_len == C::FixedSignatureSize::to_usize() {
            Ok(Self::from(array))
        } else {
            Err(crate::encoding::error::ErrorKind::Decode)?
        }
    }
}

#[cfg(all(feature = "encoding", feature = "alloc"))]
impl<C> Encode for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    /// Encode an ASN.1 encoded ECDSA signature with the given encoding
    /// (e.g. hex, Base64)
    fn encode<E: Encoding>(&self, encoding: &E) -> Vec<u8> {
        encoding.encode(self.as_ref())
    }
}

impl<C> From<GenericArray<u8, C::FixedSignatureSize>> for FixedSignature<C>
where
    C: WeierstrassCurve,
{
    fn from(bytes: GenericArray<u8, C::FixedSignatureSize>) -> Self {
        Self { bytes }
    }
}
