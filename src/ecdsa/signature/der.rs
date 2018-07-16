//! ASN.1 DER-encoded ECDSA signatures
//!
//! Presently requires 'std' as these signatures are variable-sized and the
//! current implementation is backed by a `Vec<u8>`.

use std::fmt::{self, Debug};
use std::marker::PhantomData;
// TODO: no_std support (with 'alloc' crate or fixed sized array)
use std::vec::Vec;

use ecdsa::curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures encoded as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct DERSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: Vec<u8>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> DERSignature<C> {
    /// Create an ASN.1 DER-encoded ECDSA signature from its serialized byte representation
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

impl<C: WeierstrassCurve> Debug for DERSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::DERSignature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
