//! Trait for Ed25519 verifiers
//!
//! This is intended to be used in conjunction with the `verify` method of `PublicKey`

use core::fmt::Debug;
use core::hash::Hash;

#[cfg(feature = "dalek-provider")]
pub use providers::dalek::Ed25519Verifier as DefaultVerifier;

#[cfg(all(not(feature = "dalek-provider"), feature = "ring-provider"))]
pub use providers::ring::Ed25519Verifier as DefaultVerifier;

#[cfg(all(not(feature = "dalek-provider"), not(feature = "ring-provider"),
          feature = "sodiumoxide-provider"))]
pub use providers::sodiumoxide::Ed25519Verifier as DefaultVerifier;

use error::Error;
use super::{PublicKey, Signature};

/// Verifier for Ed25519 signatures
pub trait Verifier: Clone + Debug + Hash + Eq + PartialEq + Send + Sync {
    /// Verify an Ed25519 signature against the given public key
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error>;
}

/// A panicking default verifier if no providers have been selected
#[cfg(all(not(feature = "dalek-provider"), not(feature = "ring-provider"),
          not(feature = "sodiumoxide-provider")))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct DefaultVerifier {}

#[cfg(all(not(feature = "dalek-provider"), not(feature = "ring-provider"),
          not(feature = "sodiumoxide-provider")))]
impl Verifier for DefaultVerifier {
    fn verify(_key: &PublicKey, _msg: &[u8], _signature: &Signature) -> Result<(), Error> {
        panic!("no Ed25519 providers enabled when signatory was built");
    }
}
