//! Trait for Ed25519 verifiers
//!
//! This is intended to be used in conjunction with the `verify` method of `PublicKey`

use core::fmt::Debug;
use core::hash::Hash;

use super::{PublicKey, Signature};
use error::Error;

/// Verifier for Ed25519 signatures
pub trait Verifier: Clone + Debug + Hash + Eq + PartialEq + Send + Sync {
    /// Verify an Ed25519 signature against the given public key
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error>;
}

#[cfg(feature = "dalek-provider")]
pub use providers::dalek::Ed25519Verifier as DefaultVerifier;

#[cfg(all(not(feature = "dalek-provider"), feature = "ring-provider"))]
pub use providers::ring::Ed25519Verifier as DefaultVerifier;

#[cfg(
    all(
        not(feature = "dalek-provider"),
        not(feature = "ring-provider"),
        feature = "sodiumoxide-provider"
    )
)]
pub use providers::sodiumoxide::Ed25519Verifier as DefaultVerifier;
