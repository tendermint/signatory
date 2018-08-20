//! Traits for ECDSA signers, generic over `WeierstrassCurve`.
//!
//! Signatory presently provides three different ECDSA signer traits:
//!
//! * `SHA256Signer`: computes the SHA-256 digest of a message prior to
//!   signing it. This is almost certainly what you want to use.
//!   This trait is only available for curves with a 256-bit modulus,
//!   which as it so happens is all this library supports.
//! * `DigestSigner` (when `digest` cargo feature enabled) signs a prehashed
//!   message with the prehash computed using a type that implements the
//!   `Digest` trait.
//! * `RawDigestSigner`: computes an ECDSA signature of a raw digest
//!   without first computing e.g. SHA-256. This trait is primarily
//!   intended for providers to implement if they don't have a way
//!   of easily computing SHA-256 first.

use curve::WeierstrassCurve;
use ecdsa::PublicKey;
use error::Error;

#[cfg(feature = "digest")]
mod digest;
mod raw_digest;
mod sha256;

#[cfg(feature = "digest")]
pub use self::digest::DigestSigner;
pub use self::raw_digest::RawDigestSigner;
pub use self::sha256::SHA256Signer;

/// ECDSA signer base trait
pub trait Signer<C: WeierstrassCurve>: Send + Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<C>, Error>;
}
