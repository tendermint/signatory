//! *ring* ECDSA benchmarks

#![deny(warnings)]

#[macro_use]
extern crate criterion;
use signatory;

use criterion::Criterion;
use signatory::{
    ecdsa::{
        curve::nistp256::{self, FixedSignature},
        PublicKey,
    },
    encoding::FromPkcs8,
    generic_array::GenericArray,
    test_vector::TestVector,
    Signature, Signer as _, Verifier as _,
};
use signatory_ring::ecdsa::p256::{Signer, Verifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &nistp256::SHA256_FIXED_SIZE_TEST_VECTORS[0];

fn sign_ecdsa_p256(c: &mut Criterion) {
    let signer = Signer::from_pkcs8(&TEST_VECTOR.to_pkcs8()).unwrap();

    c.bench_function("ring: ECDSA (nistp256) signer", move |b| {
        b.iter(|| {
            let _: FixedSignature = signer.sign(TEST_VECTOR.msg);
        })
    });
}

fn verify_ecdsa_p256(c: &mut Criterion) {
    let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();
    let verifier = Verifier::from(&PublicKey::from_untagged_point(GenericArray::from_slice(
        TEST_VECTOR.pk,
    )));

    c.bench_function("ring: ECDSA (nistp256) verifier", move |b| {
        b.iter(|| {
            verifier.verify(TEST_VECTOR.msg, &signature).unwrap();
        })
    });
}

criterion_group! {
    name = ecdsa_p256;
    config = Criterion::default();
    targets = sign_ecdsa_p256, verify_ecdsa_p256
}

criterion_main!(ecdsa_p256);
