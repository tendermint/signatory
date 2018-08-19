//! Traits for ECDSA verifier, generic over `WeierstrassCurve`.
//!
//! Signatory presently provides three different ECDSA verifier traits:
//!
//! * `SHA256Verifier`: computes the SHA-256 digest of a message prior to
//!   verifying it. This is almost certainly what you want to use.
//!   This trait is only available for curves with a 256-bit modulus,
//!   which as it so happens is all this library supports.
//! * `DigestVerifier` (when `digest` cargo feature enabled) verifies a
//!   prehashed message with the prehash computed using a type that implements
//!   the `Digest` trait.
//! * `RawDigestVerifier`: verifies a raw digest using ECDSA without first
//!   without first computing e.g. SHA-256. This trait is primarily intended
//!   for providers to implement.

#[cfg(feature = "digest")]
mod digest;
mod raw_digest;
mod sha256;

#[cfg(feature = "digest")]
pub use self::digest::DigestVerifier;
pub use self::raw_digest::RawDigestVerifier;
pub use self::sha256::SHA256Verifier;
