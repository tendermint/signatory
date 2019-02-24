//! Compressed and uncompressed Weierstrass elliptic curve points serialized
//! according to the `Elliptic-Curve-Point-to-Octet-String` algorithm described
//! in SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3 (page 10)
//!
//! <http://www.secg.org/sec1-v2.pdf>

use super::WeierstrassCurve;
use crate::error::Error;
use generic_array::{ArrayLength, GenericArray};

/// Compressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm
#[derive(Hash, Eq, PartialEq)]
pub struct CompressedCurvePoint<C: WeierstrassCurve> {
    /// Raw serialized bytes of the compressed point
    bytes: GenericArray<u8, C::CompressedPointSize>,
}

impl<C> CompressedCurvePoint<C>
where
    C: WeierstrassCurve,
{
    /// Create a new compressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Result<Self, Error>
    where
        B: Into<GenericArray<u8, C::CompressedPointSize>>,
    {
        let bytes = into_bytes.into();
        let tag_byte = bytes.as_ref()[0];

        ensure!(
            tag_byte == 0x02 || tag_byte == 0x03,
            KeyInvalid,
            "expected first byte to be 0x02 or 0x03 (got {})",
            tag_byte
        );

        Ok(Self { bytes })
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::CompressedPointSize> {
        self.bytes
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for CompressedCurvePoint<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C> Copy for CompressedCurvePoint<C>
where
    C: WeierstrassCurve,
    <<C as WeierstrassCurve>::CompressedPointSize as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C: WeierstrassCurve> Clone for CompressedCurvePoint<C> {
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes.clone()).unwrap()
    }
}

/// Uncompressed elliptic curve points serialized according to the
/// `Elliptic-Curve-Point-to-Octet-String` algorithm, including the `0x04`
/// tag identifying the bytestring as a curve point.
#[derive(Hash, Eq, PartialEq)]
pub struct UncompressedCurvePoint<C: WeierstrassCurve> {
    /// Raw serialized bytes of the uncompressed point
    bytes: GenericArray<u8, C::UncompressedPointSize>,
}

impl<C> UncompressedCurvePoint<C>
where
    C: WeierstrassCurve,
{
    /// Create a new uncompressed elliptic curve point
    pub fn from_bytes<B>(into_bytes: B) -> Result<Self, Error>
    where
        B: Into<GenericArray<u8, C::UncompressedPointSize>>,
    {
        let bytes = into_bytes.into();

        ensure!(
            bytes.as_ref()[0] == 0x04,
            KeyInvalid,
            "expected first byte to be 0x04 (got {})",
            bytes.as_ref()[0]
        );

        Ok(Self { bytes })
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::UncompressedPointSize> {
        self.bytes
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for UncompressedCurvePoint<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C> Copy for UncompressedCurvePoint<C>
where
    C: WeierstrassCurve,
    <<C as WeierstrassCurve>::UncompressedPointSize as ArrayLength<u8>>::ArrayType: Copy,
{
}

impl<C: WeierstrassCurve> Clone for UncompressedCurvePoint<C> {
    fn clone(&self) -> Self {
        Self::from_bytes(self.bytes.clone()).unwrap()
    }
}
