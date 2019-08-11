//! Macro for generating shared tests for all software Ed25519 implementations

/// Generate tests for Ed25519
#[macro_export]
macro_rules! ed25519_tests {
    ($signer:ident, $verifier:ident) => {
        use $crate::ed25519::{self, SIGNATURE_SIZE, TEST_VECTORS};
        use $crate::signature::{Signer as _, Verifier as _};

        #[test]
        fn sign_rfc8032_test_vectors() {
            for vector in TEST_VECTORS {
                let seed = ed25519::Seed::from_bytes(vector.sk).unwrap();
                let signer = $signer::from(&seed);
                assert_eq!(signer.sign(vector.msg).as_ref(), vector.sig);
            }
        }

        #[test]
        fn verify_rfc8032_test_vectors() {
            use $crate::signature::Signature;
            for vector in TEST_VECTORS {
                let pk = ed25519::PublicKey::from_bytes(vector.pk).unwrap();
                let verifier = $verifier::from(&pk);
                let sig = ed25519::Signature::from_bytes(vector.sig).unwrap();
                assert!(
                    verifier.verify(vector.msg, &sig).is_ok(),
                    "expected signature to verify"
                );
            }
        }

        #[test]
        fn rejects_tweaked_rfc8032_test_vectors() {
            use $crate::signature::Signature;
            for vector in TEST_VECTORS {
                let pk = ed25519::PublicKey::from_bytes(vector.pk).unwrap();
                let verifier = $verifier::from(&pk);

                let mut tweaked_sig = [0u8; SIGNATURE_SIZE];
                tweaked_sig.copy_from_slice(vector.sig);
                tweaked_sig[0] ^= 0x42;

                let result = verifier.verify(
                    vector.msg,
                    &ed25519::Signature::from_bytes(&tweaked_sig[..]).unwrap(),
                );

                assert!(
                    result.is_err(),
                    "expected signature verification failure but it succeeded"
                );
            }
        }
    };
}
