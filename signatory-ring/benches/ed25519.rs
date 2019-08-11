//! *ring* Ed25519 benchmarks

#![deny(warnings)]

#[macro_use]
extern crate criterion;
use signatory;

use criterion::Criterion;
use signatory::{
    ed25519::TEST_VECTORS,
    signature::{Signature, Signer, Verifier},
    test_vector::TestVector,
};
use signatory_ring::ed25519;

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

fn sign_ed25519(c: &mut Criterion) {
    let signer = ed25519::Signer::from(&ed25519::Seed::from_bytes(TEST_VECTOR.sk).unwrap());

    c.bench_function("ring: Ed25519 signer", move |b| {
        b.iter(|| signer.sign(TEST_VECTOR.msg))
    });
}

fn verify_ed25519(c: &mut Criterion) {
    let pk = ed25519::PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
    let sig = ed25519::Signature::from_bytes(TEST_VECTOR.sig).unwrap();
    let verifier = ed25519::Verifier::from(&pk);

    c.bench_function("ring: Ed25519 verifier", move |b| {
        b.iter(|| verifier.verify(TEST_VECTOR.msg, &sig).unwrap())
    });
}

criterion_group! {
    name = ed25519;
    config = Criterion::default();
    targets = sign_ed25519, verify_ed25519
}

criterion_main!(ed25519);
