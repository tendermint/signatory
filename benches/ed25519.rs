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
    use signatory::providers::{DalekSigner, DalekVerifier};

    fn sign(c: &mut Criterion) {
        let signer = DalekSigner::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("DalekSigner (ed25519)", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<DalekVerifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("DalekVerifier (ed25519)", move |b| {
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
    use signatory::providers::{RingSigner, RingVerifier};

    fn sign(c: &mut Criterion) {
        let signer = RingSigner::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("RingSigner (ed25519)", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<RingVerifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("RingVerifier (ed25519)", move |b| {
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
    use signatory::providers::{SodiumOxideSigner, SodiumOxideVerifier};

    fn sign(c: &mut Criterion) {
        let signer = SodiumOxideSigner::from_seed(TEST_VECTOR.sk).unwrap();

        c.bench_function("SodiumOxideSigner (ed25519)", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify(c: &mut Criterion) {
        let public_key = PublicKey::<SodiumOxideVerifier>::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("SodiumOxideVerifier (ed25519)", move |b| {
            b.iter(|| public_key.verify(TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = sodiumoxide_benches;
        config = Criterion::default();
        targets = sign, verify
    }
}

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
