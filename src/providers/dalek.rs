use error::{Error, ErrorKind};
use ed25519::{Signature, Signer};
use ed25519::PublicKey as SignatoryPublicKey;

use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use sha2::Sha512;

/// Ed25519 signature provider for ed25519-dalek
pub struct DalekSigner(Keypair);

impl DalekSigner {
    /// Create a new DalekSigner from an unexpanded seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_bytes(seed).or(Err(ErrorKind::InvalidKey))?;
        let pk = PublicKey::from_secret::<Sha512>(&sk);

        Ok(DalekSigner(Keypair {
            secret: sk,
            public: pk,
        }))
    }
}

impl Signer for DalekSigner {
    fn public_key(&self) -> Result<SignatoryPublicKey, Error> {
        Ok(SignatoryPublicKey::new(self.0.public.as_bytes()))
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::new(&self.0.sign::<Sha512>(msg).to_bytes()[..]))
    }
}

#[cfg(test)]
mod tests {
    use ed25519::{Signer, TEST_VECTORS};
    use super::DalekSigner;

    #[test]
    fn rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let mut signer = DalekSigner::from_seed(vector.sk).expect("decode error");
            assert_eq!(signer.sign(vector.msg).unwrap().as_ref(), vector.sig);
        }
    }
}
