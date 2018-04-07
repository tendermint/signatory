//! Raw (a.k.a. compact, fixed-sized) ECDSA signatures as seen with e.g. PKCS#11

use core::fmt;
use core::marker::PhantomData;
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;

use error::Error;
use ecdsa::curve::WeierstrassCurve;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures serialized in a compact, fixed-sized form
#[derive(Clone, PartialEq, Eq)]
pub struct RawSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::RawSignatureSize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> RawSignature<C> {
    /// Create an ECDSA signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            bytes.as_ref().len() == C::RawSignatureSize::to_usize(),
            SignatureInvalid,
            "expected {}-byte signature (got {})",
            C::RawSignatureSize::to_usize(),
            bytes.as_ref().len()
        );

        Ok(Self {
            bytes: GenericArray::clone_from_slice(bytes.as_ref()),
            curve: PhantomData,
        })
    }

    /// Obtain signature as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Convert signature into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::RawSignatureSize> {
        self.bytes
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for RawSignature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: WeierstrassCurve> fmt::Debug for RawSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::Signature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
