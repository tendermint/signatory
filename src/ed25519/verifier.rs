//! Trait for Ed25519 verifiers
//!
//! This is intended to be used in conjunction with the `verify` method of `PublicKey`

use core::fmt::Debug;
use core::hash::Hash;

use super::{Ed25519Signature, PublicKey};
use error::Error;

/// Verifier for Ed25519 signatures
pub trait Verifier: Clone + Debug + Hash + Eq + PartialEq + Send + Sync {
    /// Verify an Ed25519 signature against the given public key
    fn verify(key: &PublicKey, msg: &[u8], signature: &Ed25519Signature) -> Result<(), Error>;
}
