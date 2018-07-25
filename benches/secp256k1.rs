//! secp256k1 provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;

#[cfg(feature = "secp256k1-provider")]
mod secp256k1_ecdsa {
    use criterion::Criterion;
    use signatory::ecdsa::{
        curve::secp256k1::SHA256_FIXED_SIZE_TEST_VECTORS, signer::*, verifier::*, FixedSignature,
        PublicKey,
    };
    use signatory::{
        providers::secp256k1::{ECDSASigner, ECDSAVerifier},
        test_vector::TestVector,
    };

    /// Test vector to use for benchmarking
    const TEST_VECTOR: &TestVector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

    fn sign_ecdsa(c: &mut Criterion) {
        let signer = ECDSASigner::from_bytes(TEST_VECTOR.sk).unwrap();

        c.bench_function("secp256k1: ECDSA signer", move |b| {
            b.iter(|| signer.sign_sha256_fixed(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify_ecdsa(c: &mut Criterion) {
        let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("secp256k1: ECDSA verifier", move |b| {
            b.iter(|| {
                ECDSAVerifier::verify_sha256_fixed_signature(
                    &public_key,
                    TEST_VECTOR.msg,
                    &signature,
                ).unwrap()
            })
        });
    }

    criterion_group! {
        name = secp256k1_ecdsa;
        config = Criterion::default();
        targets = sign_ecdsa, verify_ecdsa
    }
}

#[cfg(feature = "secp256k1-provider")]
criterion_main!(secp256k1_ecdsa::secp256k1_ecdsa);

#[cfg(not(feature = "secp256k1-provider"))]
fn main() {
    eprintln!("*** skipping secp256k1 benchmarks: 'secp256k1-provider' cargo feature not enabled");
}
