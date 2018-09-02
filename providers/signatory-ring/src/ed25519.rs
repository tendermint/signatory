//! Ed25519 signer and verifier implementation for *ring*

use ring;
use ring::signature::Ed25519KeyPair;
use untrusted;

use signatory::{
    ed25519::{Ed25519Signature, FromSeed, PublicKey, Seed},
    encoding::FromPkcs8,
    error::{Error, ErrorKind::SignatureInvalid},
    PublicKeyed, Signature, Signer, Verifier,
};

/// Ed25519 signature provider for *ring*
pub struct Ed25519Signer(Ed25519KeyPair);

impl FromSeed for Ed25519Signer {
    /// Create a new Ed25519Signer from an unexpanded seed value
    fn from_seed<S: Into<Seed>>(seed: S) -> Self {
        let keypair = Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(
            &seed.into().0[..],
        )).unwrap();

        Ed25519Signer(keypair)
    }
}

impl FromPkcs8 for Ed25519Signer {
    /// Create a new Ed25519Signer from a PKCS#8 encoded private key
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let keypair = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(pkcs8_bytes))
            .map_err(|_| err!(KeyInvalid, "invalid PKCS#8 private key"))?;

        Ok(Ed25519Signer(keypair))
    }
}

impl PublicKeyed<PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public_key_bytes()).unwrap())
    }
}

impl<'a> Signer<&'a [u8], Ed25519Signature> for Ed25519Signer {
    fn sign(&self, msg: &'a [u8]) -> Result<Ed25519Signature, Error> {
        Ok(Ed25519Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifier for *ring*
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Verifier(PublicKey);

impl<'a> From<&'a PublicKey> for Ed25519Verifier {
    fn from(public_key: &'a PublicKey) -> Self {
        Ed25519Verifier(*public_key)
    }
}

impl<'a> Verifier<&'a [u8], Ed25519Signature> for Ed25519Verifier {
    fn verify(&self, msg: &'a [u8], signature: &Ed25519Signature) -> Result<(), Error> {
        ring::signature::verify(
            &ring::signature::ED25519,
            untrusted::Input::from(self.0.as_bytes()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_bytes()),
        ).map_err(|_| SignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
