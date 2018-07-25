//! *ring* provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;

#[cfg(feature = "ring-provider")]
mod ring_ecdsa {
    use criterion::Criterion;
    use signatory::ecdsa::{curve::nistp256, signer::*, verifier::*, FixedSignature, PublicKey};
    use signatory::{
        providers::ring::{P256FixedSigner, P256FixedVerifier},
        test_vector::TestVector,
    };

    /// Test vector to use for benchmarking
    const TEST_VECTOR: &TestVector = &nistp256::SHA256_FIXED_SIZE_TEST_VECTORS[0];

    fn sign_ecdsa_p256(c: &mut Criterion) {
        let signer = P256FixedSigner::from_test_vector(TEST_VECTOR);

        c.bench_function("ring: ECDSA (nistp256) signer", move |b| {
            b.iter(|| signer.sign_sha256_fixed(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify_ecdsa_p256(c: &mut Criterion) {
        let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("ring: ECDSA (nistp256) verifier", move |b| {
            b.iter(|| {
                P256FixedVerifier::verify_sha256_fixed_signature(
                    &public_key,
                    TEST_VECTOR.msg,
                    &signature,
                ).unwrap()
            })
        });
    }

    criterion_group! {
        name = ring_ecdsa_p256;
        config = Criterion::default();
        targets = sign_ecdsa_p256, verify_ecdsa_p256
    }
}

#[cfg(feature = "ring-provider")]
mod ring_ed25519 {
    use criterion::Criterion;
    use signatory::{
        ed25519::{FromSeed, PublicKey, Seed, Signature, Signer, Verifier, TEST_VECTORS},
        providers::ring::{Ed25519Signer, Ed25519Verifier},
        test_vector::TestVector,
    };

    /// Test vector to use for benchmarking
    const TEST_VECTOR: &TestVector = &TEST_VECTORS[4];

    fn sign_ed25519(c: &mut Criterion) {
        let signer = Ed25519Signer::from_seed(Seed::from_slice(TEST_VECTOR.sk).unwrap());

        c.bench_function("ring: ed25519 signer", move |b| {
            b.iter(|| signer.sign(TEST_VECTOR.msg).unwrap())
        });
    }

    fn verify_ed25519(c: &mut Criterion) {
        let public_key = PublicKey::from_bytes(TEST_VECTOR.pk).unwrap();
        let signature = Signature::from_bytes(TEST_VECTOR.sig).unwrap();

        c.bench_function("ring: ed25519 verifier", move |b| {
            b.iter(|| Ed25519Verifier::verify(&public_key, TEST_VECTOR.msg, &signature).unwrap())
        });
    }

    criterion_group! {
        name = ring_ed25519;
        config = Criterion::default();
        targets = sign_ed25519, verify_ed25519
    }
}

#[cfg(feature = "ring-provider")]
criterion_main!(ring_ecdsa::ring_ecdsa_p256, ring_ed25519::ring_ed25519);

#[cfg(not(feature = "ring-provider"))]
fn main() {
    eprintln!("*** skipping ring benchmarks: 'ring-provider' cargo feature not enabled");
}
