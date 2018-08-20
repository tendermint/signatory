//! secp256k1 provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;
extern crate signatory_secp256k1;

use criterion::Criterion;
use signatory::{
    curve::secp256k1::SHA256_FIXED_SIZE_TEST_VECTORS,
    ecdsa::{signer::*, verifier::*, FixedSignature, PublicKey},
    generic_array::GenericArray,
    test_vector::TestVector,
};
use signatory_secp256k1::{ECDSASigner, ECDSAVerifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

fn sign_ecdsa(c: &mut Criterion) {
    let signer = ECDSASigner::from_bytes(TEST_VECTOR.sk).unwrap();

    c.bench_function("secp256k1: ECDSA signer", move |b| {
        b.iter(|| signer.sign_sha256_fixed(TEST_VECTOR.msg).unwrap())
    });
}

fn verify_ecdsa(c: &mut Criterion) {
    let public_key =
        PublicKey::from_compressed_point(GenericArray::clone_from_slice(TEST_VECTOR.pk)).unwrap();
    let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();

    c.bench_function("secp256k1: ECDSA verifier", move |b| {
        b.iter(|| {
            ECDSAVerifier::verify_sha256_fixed_signature(&public_key, TEST_VECTOR.msg, &signature)
                .unwrap()
        })
    });
}

criterion_group! {
    name = ecdsa;
    config = Criterion::default();
    targets = sign_ecdsa, verify_ecdsa
}

criterion_main!(ecdsa);
