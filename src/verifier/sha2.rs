#[cfg(all(feature = "digest", feature = "sha2"))]
use digest::Input;
#[cfg(all(feature = "digest", feature = "sha2"))]
use sha2::{Sha256, Sha384, Sha512};

#[cfg(all(feature = "digest", feature = "sha2"))]
use super::digest::DigestVerifier;
use {Error, Signature};

/// Verifier which computes SHA-256 digests of messages
pub trait Sha256Verifier<'a, S>
where
    S: Signature,
{
    /// Verify a signature of the SHA-256 digest of a message
    fn verify_sha256(&self, msg: &'a [u8], signature: &S) -> Result<(), Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<'a, S, T> Sha256Verifier<'a, S> for T
where
    S: Signature,
    T: DigestVerifier<Sha256, S>,
{
    fn verify_sha256(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        self.verify_digest(sha256, signature)
    }
}

/// Verifier which computes SHA-384 digests of messages
pub trait Sha384Verifier<'a, S>
where
    S: Signature,
{
    /// Verify a signature of the SHA-384 digest of a message
    fn verify_sha384(&self, msg: &'a [u8], signature: &S) -> Result<(), Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<'a, S, T> Sha384Verifier<'a, S> for T
where
    S: Signature,
    T: DigestVerifier<Sha384, S>,
{
    fn verify_sha384(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        let mut sha384 = Sha384::default();
        sha384.process(msg);
        self.verify_digest(sha384, signature)
    }
}

/// Verifier which computes SHA-512 digests of messages
pub trait Sha512Verifier<'a, S>
where
    S: Signature,
{
    /// Verify a signature of the SHA-512 digest of a message
    fn verify_sha512(&self, msg: &'a [u8], signature: &S) -> Result<(), Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<'a, S, T> Sha512Verifier<'a, S> for T
where
    S: Signature,
    T: DigestVerifier<Sha512, S>,
{
    fn verify_sha512(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        let mut sha512 = Sha512::default();
        sha512.process(msg);
        self.verify_digest(sha512, signature)
    }
}

/// Verify SHA-256 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Verifier` and `Signature` traits
pub fn verify_sha256<'a, S>(
    verifier: &Sha256Verifier<'a, S>,
    msg: &'a [u8],
    signature: &S,
) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify_sha256(msg, signature)
}

/// Verify SHA-384 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Verifier` and `Signature` traits
pub fn verify_sha384<'a, S>(
    verifier: &Sha384Verifier<'a, S>,
    msg: &'a [u8],
    signature: &S,
) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify_sha384(msg, signature)
}

/// Verify SHA-512 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Verifier` and `Signature` traits
pub fn verify_sha512<'a, S>(
    verifier: &Sha512Verifier<'a, S>,
    msg: &'a [u8],
    signature: &S,
) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify_sha512(msg, signature)
}
