//! The Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! FIPS 186-4 (Digital Signature Standard)

pub mod curve;
mod public_key;
mod signature;
pub mod signer;
pub mod verifier;

pub use self::curve::Secp256k1;
pub use self::public_key::PublicKey;
pub use self::signature::der::DERSignature;
pub use self::signature::fixed::FixedSignature;
