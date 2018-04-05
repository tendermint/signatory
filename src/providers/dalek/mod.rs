//! ed25519-dalek provider: supports Ed25519 signing and verification
//!
//! A pure Rust implementation of the Ed25519 digital signature algorithm
//! utilizing several recent techniques for high-speed curve/field arithmetic.
//!
//! When the "nightly" feature is enabled, ed25519-dalek should provide the
//! best performance (on x86-64 at least) of the available Ed25519 backends
//! for both signing and signature verification.
//!
//! This provider is enabled by default.

mod ed25519;

pub use self::ed25519::{Ed25519Signer, Ed25519Verifier};
