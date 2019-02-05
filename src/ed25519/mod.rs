//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>
//!
//! This module contains two convenience methods for signing and verifying
//! Ed25519 signatures which work with any signer or verifier.
//!
//! # Example (with ed25519-dalek)
//!
//! ```
//! extern crate signatory;
//! extern crate signatory_dalek; // or another Ed25519 provider
//!
//! use signatory::ed25519;
//! use signatory_dalek::{Ed25519Signer, Ed25519Verifier};
//!
//! // Create a private key (a.k.a. a "seed") and use it to generate a signature
//! let seed = ed25519::Seed::generate();
//! let signer = Ed25519Signer::from(&seed);
//! let msg = "How are you? Fine, thank you.";
//!
//! // Sign a message
//! let sig = ed25519::sign(&signer, msg.as_bytes()).unwrap();
//!
//! // Get the public key for the given signer and make a verifier
//! let pk = ed25519::public_key(&signer).unwrap();
//! let verifier = Ed25519Verifier::from(&pk);
//! assert!(ed25519::verify(&verifier, msg.as_bytes(), &sig).is_ok());
//! ```

mod public_key;
mod seed;
mod signature;

#[cfg(feature = "test-vectors")]
#[macro_use]
mod test_macros;

/// RFC 8032 Ed25519 test vectors
#[cfg(feature = "test-vectors")]
mod test_vectors;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::TEST_VECTORS;
pub use self::{
    public_key::{PublicKey, PUBLIC_KEY_SIZE},
    seed::{Seed, SEED_SIZE},
    signature::{Signature, SIGNATURE_SIZE},
};
use crate::{error::Error, public_key::PublicKeyed, signer::Signer, verifier::Verifier};

/// Get the public key for the given public keyed object (i.e. a `Signer`)
pub fn public_key(keyed: &PublicKeyed<PublicKey>) -> Result<PublicKey, Error> {
    keyed.public_key()
}

/// Sign the given message slice with the given Ed25519 signer
#[inline]
pub fn sign(signer: &Signer<Signature>, msg: &[u8]) -> Result<Signature, Error> {
    super::sign(signer, msg)
}

/// Verify the given message slice with the given Ed25519 verifier
#[inline]
pub fn verify(verifier: &Verifier<Signature>, msg: &[u8], sig: &Signature) -> Result<(), Error> {
    super::verify(verifier, msg, sig)
}
