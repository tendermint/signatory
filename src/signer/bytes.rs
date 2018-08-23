use super::Signer;
use error::Error;
use signature::Signature;

/// Signers which accept byte slices as inputs
pub type ByteSigner<'a, S> = Signer<&'a [u8], S>;

/// Sign the given byte slice with the given signer
pub fn sign_bytes<'a, S>(signer: &ByteSigner<'a, S>, msg: &'a [u8]) -> Result<S, Error>
where
    S: Signature,
{
    signer.sign(msg)
}
