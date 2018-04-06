//! Digital signature (i.e. Ed25519) provider for *sodiumoxide*

use sodiumoxide::crypto::sign::ed25519 as sodiumoxide_ed25519;
use sodiumoxide::crypto::sign::ed25519::{SecretKey, Seed};

use error::{Error, ErrorKind};
use ed25519::{PublicKey, Signature, Signer, Verifier, SEED_SIZE};

/// Ed25519 signature provider for *ring*
pub struct Ed25519Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Ed25519Signer {
    /// Create a new SodiumOxideSigner from an unexpanded seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.len() != SEED_SIZE {
            return Err(ErrorKind::KeyInvalid.into());
        }

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
        Ok(Signature::from_bytes(&signature.0).unwrap())
    }
}

/// Ed25519 verifier provider for *sodiumoxide*
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ed25519Verifier {}

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey<Self>, msg: &[u8], signature: &Signature) -> Result<(), Error> {
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
    use std::vec::Vec;

    use error::ErrorKind;
    use ed25519::{PublicKey, Signature, Signer, Verifier, TEST_VECTORS};
    use super::{Ed25519Signer, Ed25519Verifier};

    #[test]
    fn sign_rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let mut signer = Ed25519Signer::from_seed(vector.sk).expect("decode error");
            assert_eq!(signer.sign(vector.msg).unwrap().as_ref(), vector.sig);
        }
    }

    #[test]
    fn verify_rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let pk = PublicKey::from_bytes(vector.pk).unwrap();
            let sig = Signature::from_bytes(vector.sig).unwrap();
            assert!(
                Ed25519Verifier::verify(&pk, vector.msg, &sig).is_ok(),
                "expected signature to verify"
            );
        }
    }

    #[test]
    fn rejects_tweaked_rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let pk = PublicKey::from_bytes(vector.pk).unwrap();

            let mut tweaked_sig = Vec::from(vector.sig);
            tweaked_sig[0] ^= 0x42;

            let result = Ed25519Verifier::verify(
                &pk,
                vector.msg,
                &Signature::from_bytes(&tweaked_sig).unwrap(),
            );

            assert!(
                result.is_err(),
                "expected signature verification failure but it succeeded"
            );

            match result.err().unwrap().kind() {
                ErrorKind::SignatureInvalid => (),
                other => panic!("expected ErrorKind::SignatureInvalid, got {:?}", other),
            }
        }
    }
}
