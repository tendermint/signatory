//! Ed25519 signer and verifier implementation for *ring*

pub use signatory::ed25519::{PublicKey, Seed, Signature};

use ring::{
    self,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use signatory::{
    encoding::pkcs8::{self, FromPkcs8, GeneratePkcs8},
    Error, PublicKeyed, Signature as _,
};
use untrusted;

/// Ed25519 signature provider for *ring*
pub struct Signer(Ed25519KeyPair);

impl<'a> From<&'a Seed> for Signer {
    /// Create a new Ed25519Signer from an unexpanded seed value
    fn from(seed: &'a Seed) -> Self {
        let keypair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed.as_secret_slice()))
                .unwrap();

        Signer(keypair)
    }
}

impl FromPkcs8 for Signer {
    /// Create a new Ed25519Signer from a PKCS#8 encoded private key
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, Error> {
        let keypair = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(secret_key.as_ref()))
            .map_err(|_| Error::new())?;

        Ok(Signer(keypair))
    }
}

impl GeneratePkcs8 for Signer {
    /// Randomly generate an Ed25519 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, Error> {
        let keypair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        pkcs8::SecretKey::from_bytes(keypair.as_ref())
    }
}

impl PublicKeyed<PublicKey> for Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public_key()).unwrap())
    }
}

impl signatory::Signer<Signature> for Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifier for *ring*
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verifier(PublicKey);

impl<'a> From<&'a PublicKey> for Verifier {
    fn from(public_key: &'a PublicKey) -> Self {
        Verifier(*public_key)
    }
}

impl signatory::Verifier<Signature> for Verifier {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        ring::signature::verify(
            &ring::signature::ED25519,
            untrusted::Input::from(self.0.as_bytes()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        )
        .map_err(|_| Error::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{Signer, Verifier};
    ed25519_tests!(Signer, Verifier);
}
