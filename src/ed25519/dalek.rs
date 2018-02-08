use error::{Error, ErrorKind};
use super::{Signature, Signer};

use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use sha2::Sha512;

/// Ed25519 signer based ed25519-dalek (and vicariously curve25519-dalek) crate(s)
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
    fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign::<Sha512>(msg).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use ed25519::Signer;
    use ed25519::test_vectors::TEST_VECTORS;
    use super::DalekSigner;

    #[test]
    fn rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let signer = DalekSigner::from_seed(vector.sk).expect("decode error");
            assert_eq!(signer.sign(vector.msg).as_ref(), vector.sig);
        }
    }
}
