//! The secp256k1 elliptic curve as defined by Certicom's SECG in
//! SEC 2: Recommended Elliptic Curve Domain Parameters:
//!
//! <http://www.secg.org/sec2-v2.pdf>
//!
//! This curve is most notable for its use in Bitcoin and other cryptocurrencies.

#[cfg(feature = "test-vectors")]
mod test_vectors;

use generic_array::typenum::{U32, U33, U64, U65, U73};

use super::{WeierstrassCurve, WeierstrassCurveKind};

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::SHA256_FIXED_SIZE_TEST_VECTORS;

/// The secp256k1 elliptic curve: y² = x³ + 7 over a ~256-bit prime field
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Secp256k1;

impl WeierstrassCurve for Secp256k1 {
    /// Elliptic curve kind
    const CURVE_KIND: WeierstrassCurveKind = WeierstrassCurveKind::Secp256k1;

    /// Random 256-bit (32-byte) private scalar
    type ScalarSize = U32;

    /// Size of a compressed elliptic curve point serialized using
    /// `Elliptic-Curve-Point-to-Octet-String` encoding
    type CompressedPointSize = U33;

    /// Size of a raw uncompressed elliptic curve point sans the `0x04`
    /// tag byte added in the `UncompressedPointSize` value.
    type UntaggedPointSize = U64;

    /// Size of a raw uncompressed elliptic curve point (i.e sans the `0x04`
    /// tag added by `Elliptic-Curve-Point-to-Octet-String` encoding)
    type UncompressedPointSize = U65;

    /// Maximum size of an ASN.1 DER encoded signature
    // TODO: double check this calculation
    type Asn1SignatureMaxSize = U73;

    /// Concatenated `r || s` values (32-bytes each)
    type FixedSignatureSize = U64;
}

/// secp256k1 public key
pub type PublicKey = ::ecdsa::EcdsaPublicKey<Secp256k1>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
pub type Asn1Signature = ::ecdsa::Asn1Signature<Secp256k1>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type FixedSignature = ::ecdsa::FixedSignature<Secp256k1>;
