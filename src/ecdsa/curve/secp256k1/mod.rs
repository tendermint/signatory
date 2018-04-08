//! The secp256k1 elliptic curve as defined by Certicom's SECG.
//!
//! This curve is most notable for its use in Bitcoin and other cryptocurrencies.

mod test_vectors;

use generic_array::typenum::{U32, U33, U64};

use ecdsa::PublicKey as GenericPublicKey;
use ecdsa::RawSignature as GenericRawSignature;
#[cfg(feature = "std")]
use ecdsa::DERSignature as GenericDERSignature;
use super::WeierstrassCurve;

// TODO: mark these as pub when we have a well-vetted set of test vectors
#[allow(unused_imports)]
pub(crate) use self::test_vectors::RAW_TEST_VECTORS;

/// The secp256k1 elliptic curve: y² = x³ + 7 over a ~256-bit field
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct Secp256k1 {}

impl WeierstrassCurve for Secp256k1 {
    type PrivateKeySize = U32;
    type PublicKeySize = U33;
    type RawSignatureSize = U64;

    #[cfg(feature = "secp256k1-provider")]
    type DefaultSignatureVerifier = ::providers::secp256k1::ECDSAVerifier;

    #[cfg(not(feature = "secp256k1-provider"))]
    type DefaultSignatureVerifier = ::ecdsa::verifier::PanickingVerifier<Self>;
}

/// secp256k1 public key
pub type PublicKey = GenericPublicKey<Secp256k1>;

/// Compact, fixed-sized secp256k1 ECDSA signature
pub type RawSignature = GenericRawSignature<Secp256k1>;

/// ASN.1 DER encoded secp256k1 ECDSA signature
#[cfg(feature = "std")]
pub type DERSignature = GenericDERSignature<Secp256k1>;
