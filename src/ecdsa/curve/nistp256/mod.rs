//! The NIST P-256 (a.k.a. prime256v1, secp256r1) elliptic curve defined in
//! FIPS 186-4: Digital Signature Standard (DSS)
//!
//! <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//!
//! This curve is part of the US National Security Agency's "Suite B" and
//! and is widely used in protocols like TLS and the associated X.509 PKI.

#[cfg(feature = "test-vectors")]
mod test_vectors;

use generic_array::typenum::{U32, U64, U65, U73};

use super::WeierstrassCurve;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::SHA256_FIXED_SIZE_TEST_VECTORS;

/// The NIST P-256 elliptic curve: y² = x³ - 3x + b over a ~256-bit prime field
/// where b is "verifiably random"† constant:
///
/// b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
///
/// † NOTE: the specific origins of this constant have never been fully disclosed
///   (it is the SHA-1 digest of an inexplicable NSA-selected constant)
///
/// NIST P-256 is also known as prime256v1 (ANSI X9.62) and secp256r1 (SECG)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct NISTP256;

impl WeierstrassCurve for NISTP256 {
    /// Signatory's ID for this curve
    const ID: &'static str = "nistp256";

    /// SECG identifier for this curve
    const SECG_ID: &'static str = "secp256r1";

    /// We expect uncompressed public keys with P-256
    const COMPRESSED_PUBLIC_KEY: bool = false;

    /// Random 256-bit (32-byte) private scalar
    type PrivateScalarSize = U32;

    /// 64-byte uncompressed public point + 1-byte DER OCTET STRING tag
    type DERPublicKeySize = U65;

    /// Maximum size of an ASN.1 DER encoded signature
    // TODO: double check this calculation
    type DERSignatureMaxSize = U73;

    /// Concatenated `r || s` values (32-bytes each)
    type FixedSignatureSize = U64;
}

/// NIST P-256 public key
pub type PublicKey = ::ecdsa::PublicKey<NISTP256>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
pub type DERSignature = ::ecdsa::DERSignature<NISTP256>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type FixedSignature = ::ecdsa::FixedSignature<NISTP256>;
