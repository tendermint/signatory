//! Ed25519: Schnorr signatures using the twisted Edwards form of Curve25519
//!
//! Described in RFC 8032: <https://tools.ietf.org/html/rfc8032>
//!
//! This module contains two convenience methods for signing and verifying
//! Ed25519 signatures which work with any signer or verifier.
//!
//! # Example (with ed25519-dalek)
//!
//! ```nobuild
//! extern crate signatory;
//! extern crate signatory_dalek; // or another Ed25519 provider
//!
//! use signatory::{ed25519, Ed25519Seed, FromEd25519Seed};
//! use signatory_dalek::{Ed25519Signer, Ed25519Verifier};
//!
//! // Create a private key (a.k.a. a "seed") and use it to generate a signature
//! let seed = Ed25519Seed::generate();
//! let signer = Ed25519Signer::from_seed(seed);
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

#[macro_use]
mod test_macros;

/// RFC 8032 Ed25519 test vectors
#[cfg(feature = "test-vectors")]
mod test_vectors;

#[cfg(feature = "test-vectors")]
pub use self::test_vectors::TEST_VECTORS;
pub use self::{
    public_key::{Ed25519PublicKey, PUBLIC_KEY_SIZE},
    seed::{FromSeed, Seed, SEED_SIZE},
    signature::{Ed25519Signature, SIGNATURE_SIZE},
};
use error::Error;
use public_key::PublicKeyed;
use signer::Signer;
use verifier::Verifier;

/// Get the public key for the given public keyed object (i.e. a `Signer`)
pub fn public_key(keyed: &PublicKeyed<Ed25519PublicKey>) -> Result<Ed25519PublicKey, Error> {
    keyed.public_key()
}

/// Sign the given message slice with the given Ed25519 signer
#[inline]
pub fn sign(signer: &Signer<Ed25519Signature>, msg: &[u8]) -> Result<Ed25519Signature, Error> {
    super::sign(signer, msg)
}

/// Verify the given message slice with the given Ed25519 verifier
#[inline]
pub fn verify(
    verifier: &Verifier<Ed25519Signature>,
    msg: &[u8],
    sig: &Ed25519Signature,
) -> Result<(), Error> {
    super::verify(verifier, msg, sig)
}
