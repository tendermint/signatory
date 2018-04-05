//! sodiumoxide provider: supports Ed25519 signing and verification
//!
//! A Rust wrapper for the popular libsodium cryptography library. Requires
//! libsodium is installed as an external dependency (i.e. through the OS's
//! package manager)

mod ed25519;

pub use self::ed25519::{Ed25519Signer, Ed25519Verifier};
