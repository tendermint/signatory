//! secp256k1-rs provider: supports ECDSA signing (verification coming soon!)
//!
//! A high-performance implementation of secp256k1 elliptic curve operations,
//! including ECDSA signatures.

mod ecdsa;

pub use self::ecdsa::{ECDSASigner, ECDSAVerifier};
