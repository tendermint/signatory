//! Digital signature (i.e. Ed25519) provider for *sodiumoxide*

use sodiumoxide::crypto::sign::ed25519 as sodiumoxide_ed25519;
use sodiumoxide::crypto::sign::ed25519::{SecretKey, Seed};

use error::{Error, ErrorKind};
use ed25519::{FromSeed, PublicKey, Signature, Signer, Verifier, SEED_SIZE};

/// Ed25519 signature provider for *ring*
pub struct Ed25519Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl FromSeed for Ed25519Signer {
    /// Create a new SodiumOxideSigner from an unexpanded seed value
    fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        ensure!(
            seed.len() == SEED_SIZE,
            KeyInvalid,
            "expected {}-byte seed (got {})",
            SEED_SIZE,
            seed.len()
        );

        let (public_key, secret_key) =
            sodiumoxide_ed25519::keypair_from_seed(&Seed::from_slice(seed).unwrap());

        Ok(Self {
            secret_key,
            public_key: PublicKey::from_bytes(&public_key.0).unwrap(),
        })
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(self.public_key)
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let signature = sodiumoxide_ed25519::sign_detached(msg, &self.secret_key);
        Ok(Signature::from_bytes(&signature.0[..]).unwrap())
    }
}

/// Ed25519 verifier provider for *sodiumoxide*
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let pk = sodiumoxide_ed25519::PublicKey::from_slice(key.as_bytes()).unwrap();
        let sig = sodiumoxide_ed25519::Signature::from_slice(signature.as_ref()).unwrap();

        if sodiumoxide_ed25519::verify_detached(&sig, msg, &pk) {
            Ok(())
        } else {
            Err(ErrorKind::SignatureInvalid.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
