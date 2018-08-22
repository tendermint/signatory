#[cfg(all(feature = "digest", feature = "sha2"))]
use digest::Input;
#[cfg(all(feature = "digest", feature = "sha2"))]
use sha2::Sha256;

#[cfg(all(feature = "digest", feature = "sha2"))]
use super::digest::DigestSigner;
use error::Error;
use signature::Signature;

/// Signer which computes SHA-256 digests of messages
pub trait Sha256Signer<'a, S>
where
    S: Signature,
{
    /// Compute a signature of the SHA-256 digest of a message
    fn sign_sha256(&self, msg: &'a [u8]) -> Result<S, Error>;
}

#[cfg(all(feature = "digest", feature = "sha2"))]
impl<'a, S, T> Sha256Signer<'a, S> for T
where
    S: Signature,
    T: DigestSigner<Sha256, S>,
{
    fn sign_sha256(&self, msg: &[u8]) -> Result<S, Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        self.sign_digest(sha256)
    }
}

/// Compute SHA-256 of the given message and then sign the resulting digest.
/// This can be used to avoid importing the `Signer` and `Signature` traits
pub fn sign_sha256<'a, S>(signer: &Sha256Signer<'a, S>, msg: &'a [u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign_sha256(msg)
}
