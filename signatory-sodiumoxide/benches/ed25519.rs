//! sodiumoxide provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
use signatory;

use criterion::Criterion;
use signatory::{ed25519, test_vector::TestVector, Signature, Signer, Verifier};
use signatory_sodiumoxide::{Ed25519Signer, Ed25519Verifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &ed25519::TEST_VECTORS[4];

fn sign_ed25519(c: &mut Criterion) {
    let signer = Ed25519Signer::from(&ed25519::Seed::from_bytes(TEST_VECTOR.sk).unwrap());

    c.bench_function("sodiumoxide: Ed25519 signer", move |b| {
        b.iter(|| signer.sign(TEST_VECTOR.msg))
    });
}

fn verify_ed25519(c: &mut Criterion) {
    let signature = ed25519::Signature::from_bytes(TEST_VECTOR.sig).unwrap();
    let verifier = Ed25519Verifier::from(&ed25519::PublicKey::from_bytes(TEST_VECTOR.pk).unwrap());

    c.bench_function("sodiumoxide: Ed25519 verifier", move |b| {
        b.iter(|| verifier.verify(TEST_VECTOR.msg, &signature).unwrap())
    });
}

criterion_group! {
    name = ed25519;
    config = Criterion::default();
    targets = sign_ed25519, verify_ed25519
}

criterion_main!(ed25519);
