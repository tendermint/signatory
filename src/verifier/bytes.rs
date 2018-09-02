use super::Verifier;
use error::Error;
use signature::Signature;

/// Verifiers which accept byte slices as inputs
pub type ByteVerifier<'a, S> = Verifier<&'a [u8], S>;

/// Verify a message byte slice using the given public key and signature
pub fn verify_bytes<'a, S>(
    verifier: &ByteVerifier<'a, S>,
    msg: &'a [u8],
    signature: &S,
) -> Result<(), Error>
where
    S: Signature,
{
    verifier.verify(msg, signature)
}
