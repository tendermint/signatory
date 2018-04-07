//! Elliptic Curves supported for use with ECDSA

pub mod secp256k1;

use core::fmt::Debug;
use core::hash::Hash;
use generic_array::ArrayLength;

pub use self::secp256k1::Secp256k1;

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait WeierstrassCurve: Clone + Debug + Default + Hash + Eq + PartialEq + Sync + Sized {
    /// Size of a private scalar for this elliptic curve in bytes
    type PrivateKeySize: ArrayLength<u8>;

    /// Size of a compressed public point for this curve in bytes
    type PublicKeySize: ArrayLength<u8>;

    /// Size of a compact, fixed-sized signature for this curve
    type RawSignatureSize: ArrayLength<u8>;
}
