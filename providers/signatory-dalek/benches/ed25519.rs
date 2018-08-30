//! ed25519-dalek provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;
extern crate signatory_dalek;

use criterion::Criterion;
use signatory::{
    ed25519::{Ed25519Signature, FromSeed, PublicKey, Seed, Verifier, TEST_VECTORS},
    test_vector::TestVector,
    Signature,
};
use signatory_dalek::{Ed25519Signer, Ed25519Verifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

fn sign_ed25519(c: &mut Criterion) {
    let signer = Ed25519Signer::from_seed(Seed::from_bytes(TEST_VECTOR.sk).unwrap());

    c.bench_function("dalek: Ed25519 signer", move |b| {
        b.iter(|| signatory::sign(&signer, TEST_VECTOR.msg).unwrap())
    });
}

fn verify_ed25519(c: &mut Criterion) {
    let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
    let signature = Ed25519Signature::from_bytes(TEST_VECTOR.sig).unwrap();

    c.bench_function("dalek: Ed25519 verifier", move |b| {
        b.iter(|| Ed25519Verifier::verify(&public_key, TEST_VECTOR.msg, &signature).unwrap())
    });
}

criterion_group! {
    name = ed25519;
    config = Criterion::default();
    targets = sign_ed25519, verify_ed25519
}

criterion_main!(ed25519);
