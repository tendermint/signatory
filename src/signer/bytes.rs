use error::Error;
use signature::Signature;
use signer::Signer;

/// Trait for signers which accept byte slices as inputs
pub trait ByteSigner<S: Signature>: Send + Sync {
    /// Sign the given byte slice
    fn sign_bytes(&self, msg: &[u8]) -> Result<S, Error>;
}

impl<S, T> ByteSigner<S> for T
where
    S: Signature,
    T: for<'a> Signer<&'a [u8], S>,
{
    fn sign_bytes(&self, msg: &[u8]) -> Result<S, Error> {
        self.sign(msg)
    }
}

/// Sign the given `AsRef<[u8]>` type with the given signer
pub fn sign_bytes<S>(signer: &ByteSigner<S>, msg: &[u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign_bytes(msg)
}
