//! Ed25519 signer and verifier implementation for *ring*

use ring;
use ring::signature::Ed25519KeyPair;
use untrusted;

use error::{Error, ErrorKind};
use ed25519::{FromSeed, PublicKey, Signature, Signer, Verifier, SEED_SIZE};

/// Ed25519 signature provider for *ring*
pub struct Ed25519Signer(Ed25519KeyPair);

impl FromSeed for Ed25519Signer {
    /// Create a new Ed25519Signer from an unexpanded seed value
    fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        ensure!(
            seed.len() == SEED_SIZE,
            KeyInvalid,
            "expected {}-byte seed (got {})",
            SEED_SIZE,
            seed.len()
        );

        let keypair = Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed)).unwrap();
        Ok(Ed25519Signer(keypair))
    }
}

impl Ed25519Signer {
    /// Create a new Ed25519Signer from a PKCS#8 encoded private key
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, Error> {
        let keypair = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(bytes))
            .map_err(|_| err!(KeyInvalid, "invalid PKCS#8 private key"))?;

        Ok(Ed25519Signer(keypair))
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public_key_bytes()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifier provider for *ring*
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        ring::signature::verify(
            &ring::signature::ED25519,
            untrusted::Input::from(key.as_bytes()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_bytes()),
        ).map_err(|_| ErrorKind::SignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
