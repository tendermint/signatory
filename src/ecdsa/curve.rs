//! Elliptic Curves: Weierstrass form - for use with ECDSA.

pub mod nistp256;
pub mod nistp384;
pub mod point;
pub mod secp256k1;

pub use self::{nistp256::NistP256, nistp384::NistP384, secp256k1::Secp256k1};
use crate::Error;
use core::{fmt::Debug, hash::Hash, str::FromStr};
use generic_array::ArrayLength;

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait WeierstrassCurve:
    Clone + Debug + Default + Hash + Eq + PartialEq + PartialOrd + Ord + Send + Sized + Sync
{
    /// Elliptic curve kind
    const CURVE_KIND: WeierstrassCurveKind;

    // TODO: unify these sizes, either with `typenum` or after const generics
    // hopefully make this kind of type-level arithmetic easy to do.

    /// Size of an integer modulo p (i.e. the curve's order) when serialized
    /// as octets (i.e. bytes). This also describes the size of an ECDSA
    /// private key, as well as half the size of a fixed-width signature.
    type ScalarSize: ArrayLength<u8>;

    /// Size of a compressed point for this curve in bytes when serialized
    /// using `Elliptic-Curve-Point-to-Octet-String` encoding defined in
    /// section 2.3.3 of SEC 1: Elliptic Curve Cryptography (Version 2.0):
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    type CompressedPointSize: ArrayLength<u8> + Eq + Hash + PartialEq + PartialOrd + Ord;

    /// Size of a raw uncompressed elliptic curve point sans the `0x04`
    /// tag byte added in the `UncompressedPointSize` value.
    type UntaggedPointSize: ArrayLength<u8>;

    /// Size of an uncompressed elliptic curve point serialized using
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding (including the
    /// `0x04` tag)
    type UncompressedPointSize: ArrayLength<u8> + Eq + Hash + PartialEq + PartialOrd + Ord;

    /// Maximum size of an ASN.1 DER encoded ECDSA signature using this curve
    type Asn1SignatureMaxSize: ArrayLength<u8>;

    /// Size of a compact, fixed-sized ECDSA signature using this curve
    type FixedSignatureSize: ArrayLength<u8>;
}

/// Types of Weierstrass curves known to this library
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WeierstrassCurveKind {
    /// The NIST P-256 (a.k.a. prime256v1, secp256r1) elliptic curve defined in
    /// FIPS 186-4: Digital Signature Standard (DSS).
    ///
    /// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
    NistP256,

    /// The NIST P-384 (a.k.a. secp384r1) elliptic curve defined in
    /// FIPS 186-4: Digital Signature Standard (DSS).
    ///
    /// <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
    NistP384,

    /// The secp256k1 elliptic curve as defined by Certicom's SECG in
    /// SEC 2: Recommended Elliptic Curve Domain Parameters.
    ///
    /// <http://www.secg.org/sec2-v2.pdf>
    Secp256k1,
}

impl FromStr for WeierstrassCurveKind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "nistp256" => Ok(WeierstrassCurveKind::NistP256),
            "nistp384" => Ok(WeierstrassCurveKind::NistP384),
            "secp256k1" => Ok(WeierstrassCurveKind::Secp256k1),
            _ => Err(Error::new()),
        }
    }
}

impl WeierstrassCurveKind {
    /// Get the string identifier for this elliptic curve. This name matches
    /// the Signatory module name for this curve.
    pub fn to_str(self) -> &'static str {
        match self {
            WeierstrassCurveKind::NistP256 => "nistp256",
            WeierstrassCurveKind::NistP384 => "nistp384",
            WeierstrassCurveKind::Secp256k1 => "secp256k1",
        }
    }

    /// Get the SECG identifier name for this particular elliptic curve
    /// (if applicable).
    pub fn to_secg_name(self) -> Option<&'static str> {
        match self {
            WeierstrassCurveKind::NistP256 => Some("secp256r1"),
            WeierstrassCurveKind::NistP384 => Some("secp384r1"),
            WeierstrassCurveKind::Secp256k1 => Some("secp256k1"),
        }
    }
}
