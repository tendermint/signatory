//! Ed25519 provider for ed25519-dalek

use ed25519_dalek::{Keypair, SecretKey};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use sha2::Sha512;

use error::{Error, ErrorKind};
use ed25519::{PublicKey, Signature, Signer, Verifier};

/// Ed25519 signature provider for ed25519-dalek
pub struct Ed25519Signer(Keypair);

impl Ed25519Signer {
    /// Create a new DalekSigner from an unexpanded seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let sk = SecretKey::from_bytes(seed).or(Err(ErrorKind::KeyInvalid))?;
        let pk = DalekPublicKey::from_secret::<Sha512>(&sk);

        Ok(Ed25519Signer(Keypair {
            secret: sk,
            public: pk,
        }))
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
pub struct Ed25519Verifier {}

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey<Self>, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let sig = DalekSignature::from_bytes(signature.as_ref()).unwrap();

        if DalekPublicKey::from_bytes(&key.bytes)
            .unwrap()
            .verify::<Sha512>(msg, &sig)
        {
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
