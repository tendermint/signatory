//! Digital signature (i.e. Ed25519) provider for *ring*

use error::{Error, ErrorKind};
use ed25519::{PublicKey, Signature, Signer, Verifier, SEED_SIZE};

use ring;
use ring::signature::Ed25519KeyPair;
use untrusted;

/// Ed25519 signature provider for *ring*
pub struct RingSigner(Ed25519KeyPair);

impl RingSigner {
    /// Create a new RingSigner from an unexpanded seed value
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        if seed.len() != SEED_SIZE {
            return Err(ErrorKind::KeyInvalid.into());
        }

        Ok(RingSigner(
            Ed25519KeyPair::from_seed_unchecked(untrusted::Input::from(seed)).unwrap(),
        ))
    }
}

impl Signer for RingSigner {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public_key_bytes()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(self.0.sign(msg).as_ref()).unwrap())
    }
}

/// Ed25519 verifier provider for *ring*
pub struct RingVerifier {}

impl Verifier for RingVerifier {
    fn verify(key: &PublicKey<Self>, msg: &[u8], signature: &Signature) -> Result<(), Error> {
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
    use std::vec::Vec;

    use error::ErrorKind;
    use ed25519::{PublicKey, Signature, Signer, Verifier, TEST_VECTORS};
    use super::{RingSigner, RingVerifier};

    #[test]
    fn sign_rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let mut signer = RingSigner::from_seed(vector.sk).expect("decode error");
            assert_eq!(signer.sign(vector.msg).unwrap().as_ref(), vector.sig);
        }
    }

    #[test]
    fn verify_rfc8032_test_vectors() {
        for vector in TEST_VECTORS {
            let pk = PublicKey::from_bytes(vector.pk).unwrap();
            let sig = Signature::from_bytes(vector.sig).unwrap();
            assert!(
                RingVerifier::verify(&pk, vector.msg, &sig).is_ok(),
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

            let result = RingVerifier::verify(
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
