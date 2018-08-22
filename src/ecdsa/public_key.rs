//! ECDSA public keys: compressed or uncompressed Weierstrass elliptic
//! curve points.

use core::fmt::{self, Debug};
use generic_array::{typenum::Unsigned, GenericArray};

use curve::point::{CompressedCurvePoint, UncompressedCurvePoint};
use curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;
use PublicKey as PublicKeyTrait;

/// ECDSA public keys
#[derive(Clone, PartialEq)]
pub enum PublicKey<C: WeierstrassCurve> {
    /// Compressed Weierstrass elliptic curve point
    Compressed(CompressedCurvePoint<C>),

    /// Uncompressed Weierstrass elliptic curve point
    Uncompressed(UncompressedCurvePoint<C>),
}

impl<C> PublicKey<C>
where
    C: WeierstrassCurve,
{
    /// Create an ECDSA public key from an elliptic curve point
    /// (compressed or uncompressed) encoded using the
    /// `Octet-String-to-Elliptic-Curve-Point` algorithm described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.4 (page 11).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let length = slice.len();

        if length == C::CompressedPointSize::to_usize() {
            Ok(PublicKey::Compressed(CompressedCurvePoint::new(
                GenericArray::clone_from_slice(slice),
            )?))
        } else if length == C::UncompressedPointSize::to_usize() {
            Ok(PublicKey::Uncompressed(UncompressedCurvePoint::new(
                GenericArray::clone_from_slice(slice),
            )?))
        } else {
            fail!(
                KeyInvalid,
                "invalid length for {:?} public key: {}",
                C::CURVE_KIND,
                length
            );
        }
    }

    /// Create an ECDSA public key from an compressed elliptic curve point
    /// encoded using the `Octet-String-to-Elliptic-Curve-Point` algorithm
    /// described in SEC 1: Elliptic Curve Cryptography (Version 2.0) section
    /// 2.3.4 (page 11).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_compressed_point<B>(into_bytes: B) -> Result<Self, Error>
    where
        B: Into<GenericArray<u8, C::CompressedPointSize>>,
    {
        Ok(PublicKey::Compressed(CompressedCurvePoint::new(
            into_bytes,
        )?))
    }

    /// Create an ECDSA public key from a raw uncompressed point serialized
    /// as a bytestring, without a `0x04`-byte tag.
    ///
    /// This will be twice the modulus size, or 1-byte smaller than the
    /// `Octet-String-to-Elliptic-Curve-Point` encoding i.e
    /// with the leading `0x04` byte in that encoding removed.
    pub fn from_untagged_point(bytes: &GenericArray<u8, C::UntaggedPointSize>) -> Self {
        let mut tagged_bytes = GenericArray::default();
        tagged_bytes.as_mut_slice()[0] = 0x04;
        tagged_bytes.as_mut_slice()[1..].copy_from_slice(bytes.as_ref());

        PublicKey::Uncompressed(UncompressedCurvePoint::new(tagged_bytes).unwrap())
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Compressed(ref point) => point.as_bytes(),
            PublicKey::Uncompressed(ref point) => point.as_bytes(),
        }
    }
}

impl<C> AsRef<[u8]> for PublicKey<C>
where
    C: WeierstrassCurve,
{
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C> Debug for PublicKey<C>
where
    C: WeierstrassCurve,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::PublicKey<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

impl<C: WeierstrassCurve> PublicKeyTrait for PublicKey<C> {}
