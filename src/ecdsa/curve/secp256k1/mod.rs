//! The secp256k1 elliptic curve as defined by Certicom's SECG in
//! SEC 2: Recommended Elliptic Curve Domain Parameters:
//!
//! <http://www.secg.org/sec2-v2.pdf>
//!
//! This curve is most notable for its use in Bitcoin and other cryptocurrencies.

#[cfg(feature = "test-vectors")]
mod test_vectors;

use generic_array::typenum::{U32, U33, U64, U73};

use super::WeierstrassCurve;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::SHA256_FIXED_SIZE_TEST_VECTORS;

/// The secp256k1 elliptic curve: y² = x³ + 7 over a ~256-bit prime field
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Secp256k1;

impl WeierstrassCurve for Secp256k1 {
    /// Signatory's ID for this curve
    const ID: &'static str = "secp256k1";

    /// SECG identifier for this curve
    const SECG_ID: &'static str = "secp256k1";

    /// We expect compressed public keys with secp256k1
    const COMPRESSED_PUBLIC_KEY: bool = true;

    /// Random 256-bit (32-byte) private scalar
    type PrivateScalarSize = U32;

    /// 32 byte compressed public point + 1-byte DER OCTET STRING tag
    // NOTE: P-256 uses uncompressed public keys, but compressed are more
    // popular among cryptocurrencies and so we go with convention over
    // consistency for consistency's sake
    type DERPublicKeySize = U33;

    /// Maximum size of an ASN.1 DER encoded signature
    // TODO: double check this calculation
    type DERSignatureMaxSize = U73;

    /// Concatenated `r || s` values (32-bytes each)
    type FixedSignatureSize = U64;
}

/// secp256k1 public key
pub type PublicKey = ::ecdsa::PublicKey<Secp256k1>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
pub type DERSignature = ::ecdsa::DERSignature<Secp256k1>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type FixedSignature = ::ecdsa::FixedSignature<Secp256k1>;
