//! ed25519-dalek provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;

#[cfg(feature = "dalek-provider")]
mod dalek_ed25519 {
    use criterion::Criterion;
    use signatory::{
        ed25519::{FromSeed, PublicKey, Seed, Signature, Signer, Verifier, TEST_VECTORS},
        providers::dalek::{Ed25519Signer, Ed25519Verifier},
        test_vector::TestVector,
    };

    /// Test vector to use for benchmarking
    const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

    fn sign_ed25519(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(Seed::from_slice(TEST_VECTOR.sk).unwrap());

        c.bench_function("dalek: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify_ed25519(c: &mut Criterion) {
        let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("dalek: ed25519 verifier", move |b| {
            b.iter(|| Ed25519Verifier::verify(&public_key, TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = dalek_ed25519;
        config = Criterion::default();
        targets = sign_ed25519, verify_ed25519
    }
}

#[cfg(feature = "dalek-provider")]
criterion_main!(dalek_ed25519::dalek_ed25519);

#[cfg(not(feature = "dalek-provider"))]
fn main() {
    eprintln!("*** skipping dalek benchmarks: 'dalek-provider' cargo feature not enabled");
}
