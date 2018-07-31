//! Elliptic Curves (Weierstrass form) supported for use with ECDSA

pub mod nistp256;
pub mod secp256k1;

use core::fmt::Debug;
use core::hash::Hash;
use generic_array::ArrayLength;

pub use self::nistp256::NISTP256;
pub use self::secp256k1::Secp256k1;

/// Elliptic curve in short Weierstrass form suitable for use with ECDSA
pub trait WeierstrassCurve:
    Clone + Debug + Default + Hash + Eq + PartialEq + Send + Sized + Sync
{
    /// Signatory's ID for this curve (same as the `signatory::ecdsa::curve` module name)
    const ID: &'static str;

    /// SECG identifier for this curve
    const SECG_ID: &'static str;

    /// Do we expect public keys for this curve to be represented as compressed
    /// points as opposed to uncompressed?
    // TODO: ensure we're handling this correctly, and perhaps find a better abstraction
    const COMPRESSED_PUBLIC_KEY: bool;

    /// Size of a private scalar for this elliptic curve in bytes
    type PrivateScalarSize: ArrayLength<u8>;

    /// Size of a compressed public point for this curve in bytes when
    /// serialized in ASN.1 DER form
    type DERPublicKeySize: ArrayLength<u8>;

    /// Maximum size of an ASN.1 DER encoded signature
    type DERSignatureMaxSize: ArrayLength<u8>;

    /// Size of a compact, fixed-sized signature for this curve
    type FixedSignatureSize: ArrayLength<u8>;
}
