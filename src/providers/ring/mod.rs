//! *ring* provider: supports Ed25519 signing and verification
//!
//! A popular and well-maintained Rust cryptography with wide support for many
//! modern cryptographic algorithms.

mod ecdsa;
mod ed25519;

pub use self::ecdsa::*;
pub use self::ed25519::*;
