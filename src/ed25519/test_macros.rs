//! Macro for generating shared tests for all software Ed25519 implementations

#[macro_export]
macro_rules! ed25519_tests {
    ($signer:ident, $verifier:ident) => {
        use $crate::{
            ed25519::{
                self, Ed25519PublicKey, Ed25519Signature, FromSeed, Seed, SIGNATURE_SIZE,
                TEST_VECTORS,
            },
            error::ErrorKind,
            Signature,
        };

        #[test]
        fn sign_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let seed = Seed::from_bytes(vector.sk).unwrap();
                let signer = $signer::from_seed(seed);
                assert_eq!(
                    ed25519::sign(&signer, vector.msg).unwrap().as_ref(),
                    vector.sig
                );
            }
        }

        #[test]
        fn verify_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let pk = Ed25519PublicKey::from_bytes(vector.pk).unwrap();
                let verifier = $verifier::from(&pk);
                let sig = Ed25519Signature::from_bytes(vector.sig).unwrap();
                assert!(
                    ed25519::verify(&verifier, vector.msg, &sig).is_ok(),
                    "expected signature to verify"
                );
            }
        }

        #[test]
        fn rejects_tweaked_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let pk = Ed25519PublicKey::from_bytes(vector.pk).unwrap();
                let verifier = $verifier::from(&pk);

                let mut tweaked_sig = [0u8; SIGNATURE_SIZE];
                tweaked_sig.copy_from_slice(vector.sig);
                tweaked_sig[0] ^= 0x42;

                let result = ed25519::verify(
                    &verifier,
                    vector.msg,
                    &Ed25519Signature::from_bytes(&tweaked_sig[..]).unwrap(),
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
    };
}
