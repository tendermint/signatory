/// Ed25519 provider benchmarks

#[macro_use]
extern crate criterion;
extern crate signatory;

use criterion::Criterion;
use signatory::ed25519::{PublicKey, Signature, TEST_VECTORS};
use signatory::test_vector::TestVector;

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

#[cfg(feature = "dalek-provider")]
mod dalek_benches {
    use super::*;
    use signatory::ed25519::Signer;
    use signatory::providers::dalek::{Ed25519Signer, Ed25519Verifier};

    fn sign(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("dalek: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<Ed25519Verifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("dalek: ed25519 verifier", move |b| {
            b.iter(|| public_key.verify(TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = dalek_benches;
        config = Criterion::default();
        targets = sign, verify
    }
}

#[cfg(feature = "ring-provider")]
mod ring_benches {
    use super::*;
    use signatory::ed25519::Signer;
    use signatory::providers::ring::{Ed25519Signer, Ed25519Verifier};

    fn sign(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("ring: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<Ed25519Verifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("ring: ed25519 verifier", move |b| {
            b.iter(|| public_key.verify(TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = ring_benches;
        config = Criterion::default();
        targets = sign, verify
    }
}

#[cfg(feature = "sodiumoxide-provider")]
mod sodiumoxide_benches {
    use super::*;
    use signatory::ed25519::Signer;
    use signatory::providers::sodiumoxide::{Ed25519Signer, Ed25519Verifier};

    fn sign(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("sodiumoxide: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<Ed25519Verifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("sodiumoxide: ed25519 verifier", move |b| {
            b.iter(|| public_key.verify(TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = sodiumoxide_benches;
        config = Criterion::default();
        targets = sign, verify
    }
}

// TODO: there has got to be a better way to do this...

#[cfg(all(feature = "dalek-provider", not(feature = "ring-provider"),
          not(feature = "sodiumoxide-provider")))]
criterion_main!(dalek_benches::dalek_benches);

#[cfg(all(not(feature = "dalek-provider"), feature = "ring-provider",
          not(feature = "sodiumoxide-provider")))]
criterion_main!(ring_benches::ring_benches);

#[cfg(all(not(feature = "dalek-provider"), not(feature = "ring-provider"),
          feature = "sodiumoxide-provider"))]
criterion_main!(sodiumoxide_benches::sodiumoxide_benches);

#[cfg(all(feature = "dalek-provider", feature = "ring-provider",
          not(feature = "sodiumoxide-provider")))]
criterion_main!(dalek_benches::dalek_benches, ring_benches::ring_benches);

#[cfg(all(feature = "dalek-provider", not(feature = "ring-provider"),
          feature = "sodiumoxide-provider"))]
criterion_main!(
    dalek_benches::dalek_benches,
    sodiumoxide_benches::sodiumoxide_benches
);

#[cfg(all(not(feature = "dalek-provider"), feature = "ring-provider",
          feature = "sodiumoxide-provider"))]
criterion_main!(
    ring_benches::ring_benches,
    sodiumoxide_benches::sodiumoxide_benches
);

#[cfg(all(feature = "dalek-provider", feature = "ring-provider",
          feature = "sodiumoxide-provider"))]
criterion_main!(
    dalek_benches::dalek_benches,
    ring_benches::ring_benches,
    sodiumoxide_benches::sodiumoxide_benches
);
