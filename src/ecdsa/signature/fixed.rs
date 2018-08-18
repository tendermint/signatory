//! Fixed-size, compact ECDSA signatures (as used in e.g. PKCS#11)

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use ecdsa::curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures serialized in a compact, fixed-sized form
#[derive(Clone, PartialEq, Eq)]
pub struct FixedSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::FixedSignatureSize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> FixedSignature<C> {
    /// Create an ECDSA signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            bytes.as_ref().len() == C::FixedSignatureSize::to_usize(),
            SignatureInvalid,
            "expected {}-byte signature (got {})",
            C::FixedSignatureSize::to_usize(),
            bytes.as_ref().len()
        );

        Ok(Self::from(GenericArray::clone_from_slice(bytes.as_ref())))
    }

    /// Obtain signature as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Convert signature into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::FixedSignatureSize> {
        self.bytes
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for FixedSignature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: WeierstrassCurve> Debug for FixedSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::FixedSignature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

impl<C: WeierstrassCurve> From<GenericArray<u8, C::FixedSignatureSize>> for FixedSignature<C> {
    fn from(bytes: GenericArray<u8, C::FixedSignatureSize>) -> Self {
        Self {
            bytes,
            curve: PhantomData,
        }
    }
}
