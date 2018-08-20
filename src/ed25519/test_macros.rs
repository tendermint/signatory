//! Macro for generating shared tests for all software Ed25519 implementations

#[macro_export]
macro_rules! ed25519_tests {
    ($signer:ident, $verifier:ident) => {
        use $crate::ed25519::{
            FromSeed, PublicKey, Seed, Signature, Signer, Verifier, SIGNATURE_SIZE, TEST_VECTORS,
        };
        use $crate::error::ErrorKind;

        #[test]
        fn sign_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let seed = Seed::from_slice(vector.sk).unwrap();
                let mut signer = $signer::from_seed(seed);
                assert_eq!(signer.sign(vector.msg).unwrap().as_ref(), vector.sig);
            }
        }

        #[test]
        fn verify_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let pk = PublicKey::from_bytes(vector.pk).unwrap();
                let sig = Signature::from_bytes(vector.sig).unwrap();
                assert!(
                    $verifier::verify(&pk, vector.msg, &sig).is_ok(),
                    "expected signature to verify"
                );
            }
        }

        #[test]
        fn rejects_tweaked_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let pk = PublicKey::from_bytes(vector.pk).unwrap();

                let mut tweaked_sig = [0u8; SIGNATURE_SIZE];
                tweaked_sig.copy_from_slice(vector.sig);
                tweaked_sig[0] ^= 0x42;

                let result = $verifier::verify(
                    &pk,
                    vector.msg,
                    &Signature::from_bytes(&tweaked_sig[..]).unwrap(),
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
