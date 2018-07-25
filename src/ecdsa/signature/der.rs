//! ASN.1 DER-encoded ECDSA signatures

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
#[cfg(feature = "std")]
use std::vec::Vec;

use ecdsa::curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures encoded as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct DERSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::DERSignatureMaxSize>,

    /// Length of the signature in bytes (DER is variable-width)
    length: usize,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> DERSignature<C> {
    /// Create an ASN.1 DER-encoded ECDSA signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let length = bytes.as_ref().len();

        // TODO: better validate signature is well-formed ASN.1 DER
        ensure!(
            length <= C::DERSignatureMaxSize::to_usize(),
            SignatureInvalid,
            "max {}-byte signature (got {})",
            C::DERSignatureMaxSize::to_usize(),
            length
        );

        let mut array = GenericArray::default();
        array.as_mut_slice()[..length].copy_from_slice(bytes.as_ref());

        Ok(Self {
            bytes: array,
            length,
            curve: PhantomData,
        })
    }

    /// Obtain signature as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }

    /// Convert signature into a byte vector
    #[cfg(feature = "std")]
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().into()
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for DERSignature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: WeierstrassCurve> Debug for DERSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::DERSignature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
