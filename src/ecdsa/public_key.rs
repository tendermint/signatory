//! ECDSA public keys

use core::fmt;
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::curve::WeierstrassCurve;
#[cfg(feature = "std")]
use super::DERSignature;
use super::{RawSignature, Verifier};
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA public keys
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PublicKey<C: WeierstrassCurve> {
    /// Compressed elliptic curve point representing the public key
    bytes: GenericArray<u8, C::PublicKeySize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> PublicKey<C> {
    /// Create an ECDSA public key from a compressed public point
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            bytes.as_ref().len() == C::PublicKeySize::to_usize(),
            KeyInvalid,
            "expected {}-byte key (got {})",
            C::PublicKeySize::to_usize(),
            bytes.as_ref().len()
        );

        Ok(Self {
            bytes: GenericArray::clone_from_slice(bytes.as_ref()),
            curve: PhantomData,
        })
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::PublicKeySize> {
        self.bytes
    }

    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature
    #[inline]
    pub fn verify_sha2_raw_signature(
        &self,
        msg: &[u8],
        signature: &RawSignature<C>,
    ) -> Result<(), Error> {
        C::DefaultSignatureVerifier::verify_sha2_raw_signature(self, msg, signature)
    }

    /// Verify an ASN.1 DER-encoded ECDSA signature
    #[cfg(feature = "std")]
    #[inline]
    pub fn verify_sha2_der_signature(
        &self,
        msg: &[u8],
        signature: &DERSignature<C>,
    ) -> Result<(), Error> {
        C::DefaultSignatureVerifier::verify_sha2_der_signature(self, msg, signature)
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for PublicKey<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: WeierstrassCurve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::PublicKey<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
