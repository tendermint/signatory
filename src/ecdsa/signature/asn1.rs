//! ASN.1 DER-serialized ECDSA signatures

use std::fmt;
use std::marker::PhantomData;
use std::vec::Vec;

use error::Error;
use ecdsa::curve::WeierstrassCurve;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures serialized as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct DERSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: Vec<u8>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> DERSignature<C> {
    /// Create an ECDSA signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: Into<Vec<u8>>,
    {
        // TODO: validate signature is well-formed ASN.1 DER
        Ok(Self {
            bytes: bytes.into(),
            curve: PhantomData,
        })
    }

    /// Obtain signature as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Convert signature into a byte vector
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for DERSignature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: WeierstrassCurve> fmt::Debug for DERSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::Signature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
