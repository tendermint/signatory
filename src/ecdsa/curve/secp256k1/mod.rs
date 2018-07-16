//! The secp256k1 elliptic curve as defined by Certicom's SECG.
//!
//! This curve is most notable for its use in Bitcoin and other cryptocurrencies.

mod test_vectors;

use generic_array::typenum::{U32, U33, U64};

use super::WeierstrassCurve;

pub use self::test_vectors::FIXED_SIZE_TEST_VECTORS;

/// The secp256k1 elliptic curve: y² = x³ + 7 over a ~256-bit field
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Secp256k1;

impl WeierstrassCurve for Secp256k1 {
    type PrivateKeySize = U32;
    type PublicKeySize = U33;
    type FixedSignatureSize = U64;
}

/// secp256k1 public key
pub type PublicKey = ::ecdsa::PublicKey<Secp256k1>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
#[cfg(feature = "std")]
pub type DERSignature = ::ecdsa::DERSignature<Secp256k1>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type FixedSignature = ::ecdsa::FixedSignature<Secp256k1>;
