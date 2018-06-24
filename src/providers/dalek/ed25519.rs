//! Ed25519 provider for ed25519-dalek

use ed25519::{FromSeed, PublicKey, Signature, Signer, Verifier};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Keypair, SecretKey};
use error::{Error, ErrorKind};
use sha2::Sha512;

#[cfg(feature = "std")]
use ed25519::{KeyGen, SEED_SIZE};
#[cfg(feature = "std")]
use rand::OsRng;

/// Ed25519 signature provider for ed25519-dalek
pub struct Ed25519Signer(Keypair);

impl FromSeed for Ed25519Signer {
    /// Create a new DalekSigner from an unexpanded seed value
    fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_bytes(seed).or(Err(ErrorKind::KeyInvalid))?;
        let pk = DalekPublicKey::from_secret::<Sha512>(&sk);

        Ok(Ed25519Signer(Keypair {
            secret: sk,
            public: pk,
        }))
    }
}

#[cfg(feature = "std")]
impl KeyGen for Ed25519Signer {
    // Create a new DalekSigner from random number
    fn generate_key() -> Self {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let kp: Keypair = Keypair::generate::<Sha512>(&mut csprng);
        Ed25519Signer(kp)
    }
    fn seed_as_bytes(&self) -> &[u8; SEED_SIZE] {
        self.0.secret.as_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public.as_bytes()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(&self.0.sign::<Sha512>(msg).to_bytes()[..]).unwrap())
    }
}

/// Ed25519 verifier provider for ed25519-dalek
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let pk = DalekPublicKey::from_bytes(key.as_ref()).unwrap();
        let sig = DalekSignature::from_bytes(signature.as_ref()).unwrap();

        if pk.verify::<Sha512>(msg, &sig) {
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
