//! Ed25519 signer and verifier implementation for *ring*

use ring;
#[cfg(feature = "std")]
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
#[cfg(feature = "std")]
use signatory::encoding::pkcs8::{self, GeneratePkcs8};
use signatory::{
    encoding::FromPkcs8,
    error::{Error, ErrorKind},
    Ed25519PublicKey, Ed25519Seed, Ed25519Signature, PublicKeyed, Signature, Signer, Verifier,
};
use untrusted;

/// Ed25519 signature provider for *ring*
pub struct Ed25519Signer(Ed25519KeyPair);

impl<'a> From<&'a Ed25519Seed> for Ed25519Signer {
    /// Create a new Ed25519Signer from an unexpanded seed value
    fn from(seed: &'a Ed25519Seed) -> Self {
        let keypair =
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed.as_secret_slice()))
                .unwrap();

        Ed25519Signer(keypair)
    }
}

impl FromPkcs8 for Ed25519Signer {
    /// Create a new Ed25519Signer from a PKCS#8 encoded private key
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, Error> {
        let keypair = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(secret_key.as_ref()))
            .map_err(|_| Error::from(ErrorKind::KeyInvalid))?;

        Ok(Ed25519Signer(keypair))
    }
}

#[cfg(feature = "std")]
impl GeneratePkcs8 for Ed25519Signer {
    /// Randomly generate an Ed25519 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, Error> {
        let keypair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        pkcs8::SecretKey::new(keypair.as_ref())
    }
}

impl PublicKeyed<Ed25519PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<Ed25519PublicKey, Error> {
        Ok(Ed25519PublicKey::from_bytes(self.0.public_key_bytes()).unwrap())
    }
}

impl Signer<Ed25519Signature> for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, Error> {
        Ok(Ed25519Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifier for *ring*
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Verifier(Ed25519PublicKey);

impl<'a> From<&'a Ed25519PublicKey> for Ed25519Verifier {
    fn from(public_key: &'a Ed25519PublicKey) -> Self {
        Ed25519Verifier(*public_key)
    }
}

impl Verifier<Ed25519Signature> for Ed25519Verifier {
    fn verify(&self, msg: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        ring::signature::verify(
            &ring::signature::ED25519,
            untrusted::Input::from(self.0.as_bytes()),
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
