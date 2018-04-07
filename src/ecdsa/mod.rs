//! The Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! FIPS 186-4 (Digital Signature Standard)

pub mod curve;
mod public_key;
mod signature;
mod signer;

pub use self::curve::Secp256k1;
pub use self::public_key::PublicKey;
#[cfg(feature = "std")]
pub use self::signature::DERSignature;
pub use self::signature::RawSignature;
pub use self::signer::{FixedSizeInputSigner, Signer};
