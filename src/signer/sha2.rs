#[cfg(all(feature = "digest", feature = "sha2"))]
use digest::Digest;
#[cfg(all(feature = "digest", feature = "sha2"))]
use sha2::{Sha256, Sha384, Sha512};

#[cfg(all(feature = "digest", feature = "sha2"))]
use super::DigestSigner;
use error::Error;
use signature::Signature;

// TODO: define these using a macro?

/// Signer which computes SHA-256 digests of messages
pub trait Sha256Signer<S>: Send + Sync
where
    S: Signature,
{
    /// Compute a signature of the SHA-256 digest of a message
    fn sign_sha256(&self, msg: &[u8]) -> Result<S, Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<S, T> Sha256Signer<S> for T
where
    S: Signature,
    T: DigestSigner<Sha256, S>,
{
    fn sign_sha256(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign(Sha256::new().chain(msg))
    }
}

/// Signer which computes SHA-384 digests of messages
pub trait Sha384Signer<S>: Send + Sync
where
    S: Signature,
{
    /// Compute a signature of the SHA-384 digest of a message
    fn sign_sha384(&self, msg: &[u8]) -> Result<S, Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<S, T> Sha384Signer<S> for T
where
    S: Signature,
    T: DigestSigner<Sha384, S>,
{
    fn sign_sha384(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign(Sha384::new().chain(msg))
    }
}

/// Signer which computes SHA-512 digests of messages
pub trait Sha512Signer<S>: Send + Sync
where
    S: Signature,
{
    /// Compute a signature of the SHA-512 digest of a message
    fn sign_sha512(&self, msg: &[u8]) -> Result<S, Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<S, T> Sha512Signer<S> for T
where
    S: Signature,
    T: DigestSigner<Sha512, S>,
{
    fn sign_sha512(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign(Sha512::new().chain(msg))
    }
}

/// Compute SHA-256 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Signer` and `Signature` traits
pub fn sign_sha256<S>(signer: &Sha256Signer<S>, msg: &[u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign_sha256(msg)
}

/// Compute SHA-384 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Signer` and `Signature` traits
pub fn sign_sha384<S>(signer: &Sha384Signer<S>, msg: &[u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign_sha384(msg)
}

/// Compute SHA-512 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Signer` and `Signature` traits
pub fn sign_sha512<S>(signer: &Sha512Signer<S>, msg: &[u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign_sha512(msg)
}
