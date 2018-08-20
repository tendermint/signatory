//! *ring* ECDSA benchmarks

#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;
extern crate signatory_ring;

use criterion::Criterion;
use signatory::{
    curve::nistp256,
    ecdsa::{signer::*, verifier::*, FixedSignature, PublicKey},
    generic_array::GenericArray,
    pkcs8::FromPKCS8,
    test_vector::TestVector,
};
use signatory_ring::ecdsa::{P256Signer, P256Verifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &nistp256::SHA256_FIXED_SIZE_TEST_VECTORS[0];

fn sign_ecdsa_p256(c: &mut Criterion) {
    let signer = P256Signer::from_pkcs8(&TEST_VECTOR.to_pkcs8()).unwrap();

    c.bench_function("ring: ECDSA (nistp256) signer", move |b| {
        b.iter(|| signer.sign_sha256_fixed(TEST_VECTOR.msg).unwrap())
    });
}

fn verify_ecdsa_p256(c: &mut Criterion) {
    let public_key = PublicKey::from_untagged_point(GenericArray::from_slice(TEST_VECTOR.pk));
    let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();

    c.bench_function("ring: ECDSA (nistp256) verifier", move |b| {
        b.iter(|| {
            P256Verifier::verify_sha256_fixed_signature(&public_key, TEST_VECTOR.msg, &signature)
                .unwrap()
        })
    });
}

criterion_group! {
    name = ecdsa_p256;
    config = Criterion::default();
    targets = sign_ecdsa_p256, verify_ecdsa_p256
}

criterion_main!(ecdsa_p256);
