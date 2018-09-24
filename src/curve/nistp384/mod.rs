//! The NIST P-384 (a.k.a. secp384r1) elliptic curve defined in
//! FIPS 186-4: Digital Signature Standard (DSS)
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! This curve is part of the US National Security Agency's "Suite B" and
//! and is widely used in protocols like TLS and the associated X.509 PKI.

use generic_array::typenum::{U105, U48, U49, U96, U97};

use super::{WeierstrassCurve, WeierstrassCurveKind};

#[cfg(feature = "test-vectors")]
mod test_vectors;
#[cfg(feature = "test-vectors")]
pub use self::test_vectors::SHA384_FIXED_SIZE_TEST_VECTORS;

/// The NIST P-384 elliptic curve: y² = x³ - 3x + b over a ~384-bit prime field
/// where b is "verifiably random"† constant:
///
/// b = 2758019355995970587784901184038904809305690585636156852142
///     8707301988689241309860865136260764883745107765439761230575
///
/// † NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)
///
/// NIST P-384 is also known as secp384r1 (SECG)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct NistP384;

impl WeierstrassCurve for NistP384 {
    /// Elliptic curve kind
    const CURVE_KIND: WeierstrassCurveKind = WeierstrassCurveKind::NistP384;

    /// Random 384-bit (48-byte) private scalar
    type ScalarSize = U48;

    /// Size of a compressed elliptic curve point serialized using
    /// `Elliptic-Curve-Point-to-Octet-String` encoding
    type CompressedPointSize = U49;

    /// Size of a raw uncompressed elliptic curve point sans the `0x04`
    /// tag byte added in the `UncompressedPointSize` value.
    type UntaggedPointSize = U96;

    /// Size of an uncompressed elliptic curve point serialized using
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding (including the
    /// `0x04` tag)
    type UncompressedPointSize = U97;

    /// Maximum size of an ASN.1 DER encoded signature
    // TODO: double check this calculation
    type Asn1SignatureMaxSize = U105;

    /// Concatenated `r || s` values (48-bytes each)
    type FixedSignatureSize = U96;
}

/// NIST P-384 public key
pub type PublicKey = ::ecdsa::EcdsaPublicKey<NistP384>;

/// ASN.1 DER encoded secp384k1 ECDSA signature
pub type Asn1Signature = ::ecdsa::Asn1Signature<NistP384>;

/// Compact, fixed-sized secp384k1 ECDSA signature
pub type FixedSignature = ::ecdsa::FixedSignature<NistP384>;
