use error::Error;
use signature::Signature;
use verifier::Verifier;

/// Trait for verifiers which accept byte slices as inputs
pub trait ByteVerifier<S: Signature>: Send + Sync {
    /// Verify the given byte slice using the public key this verifier was
    /// instantiated with
    fn verify_bytes(&self, msg: &[u8], signature: &S) -> Result<(), Error>;
}

impl<S, T> ByteVerifier<S> for T
where
    S: Signature,
    T: for<'a> Verifier<&'a [u8], S>,
{
    fn verify_bytes(&self, msg: &[u8], signature: &S) -> Result<(), Error> {
        self.verify(msg, signature)
    }
}

/// Sign the given `AsRef<[u8]>` type with the given signer
pub fn verify_bytes<S>(verifier: &ByteVerifier<S>, msg: &[u8], sig: &S) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify_bytes(msg, sig)
}
