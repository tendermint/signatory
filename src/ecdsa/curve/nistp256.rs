//! The NIST P-256 (a.k.a. prime256v1, secp256r1) elliptic curve defined in
//! FIPS 186-4: Digital Signature Standard (DSS)
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! This curve is part of the US National Security Agency's "Suite B" and
//! and is widely used in protocols like TLS and the associated X.509 PKI.

#[cfg(feature = "test-vectors")]
mod test_vectors;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::SHA256_FIXED_SIZE_TEST_VECTORS;
use super::{WeierstrassCurve, WeierstrassCurveKind};
#[cfg(all(feature = "digest", feature = "sha2"))]
use crate::sha2::Sha256;
use generic_array::typenum::{U32, U33, U64, U65, U73};

/// The NIST P-256 elliptic curve: y² = x³ - 3x + b over a ~256-bit prime field
/// where b is "verifiably random"† constant:
///
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
///
/// † NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)
///
/// NIST P-256 is also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct NistP256;

impl WeierstrassCurve for NistP256 {
    /// Elliptic curve kind
    const CURVE_KIND: WeierstrassCurveKind = WeierstrassCurveKind::NistP256;

    /// Random 256-bit (32-byte) private scalar
    type ScalarSize = U32;

    /// Size of a compressed elliptic curve point serialized using
    /// `Elliptic-Curve-Point-to-Octet-String` encoding
    type CompressedPointSize = U33;

    /// Size of a raw uncompressed elliptic curve point sans the `0x04`
    /// tag byte added in the `UncompressedPointSize` value.
    type UntaggedPointSize = U64;

    /// Size of an uncompressed elliptic curve point serialized using
    /// the `Elliptic-Curve-Point-to-Octet-String` encoding (including the
    /// `0x04` tag)
    type UncompressedPointSize = U65;

    /// Maximum size of an ASN.1 DER encoded signature
    // TODO: double check this calculation
    type Asn1SignatureMaxSize = U73;

    /// Concatenated `r || s` values (32-bytes each)
    type FixedSignatureSize = U64;
}

/// NIST P-256 secret key
pub type SecretKey = crate::ecdsa::SecretKey<NistP256>;

/// NIST P-256 public key
pub type PublicKey = crate::ecdsa::PublicKey<NistP256>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
pub type Asn1Signature = crate::ecdsa::Asn1Signature<NistP256>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type FixedSignature = crate::ecdsa::FixedSignature<NistP256>;

#[cfg(all(feature = "digest", feature = "sha2"))]
impl_digest_signature!(Sha256, Asn1Signature, FixedSignature);
