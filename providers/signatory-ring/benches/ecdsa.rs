//! *ring* ECDSA benchmarks

#![deny(warnings)]

#[macro_use]
extern crate criterion;
extern crate signatory;
extern crate signatory_ring;

use criterion::Criterion;
use signatory::{
    curve::nistp256::{self, FixedSignature},
    ecdsa::EcdsaPublicKey,
    encoding::FromPkcs8,
    generic_array::GenericArray,
    test_vector::TestVector,
    Sha256Verifier, Signature,
};
use signatory_ring::ecdsa::{P256Signer, P256Verifier};

/// Test vector to use for benchmarking
const TEST_VECTOR: &TestVector = &nistp256::SHA256_FIXED_SIZE_TEST_VECTORS[0];

fn sign_ecdsa_p256(c: &mut Criterion) {
    let signer = P256Signer::from_pkcs8(&TEST_VECTOR.to_pkcs8()).unwrap();

    c.bench_function("ring: ECDSA (nistp256) signer", move |b| {
        b.iter(|| signatory::sign_sha256::<FixedSignature>(&signer, TEST_VECTOR.msg).unwrap())
    });
}

fn verify_ecdsa_p256(c: &mut Criterion) {
    let signature = FixedSignature::from_bytes(TEST_VECTOR.sig).unwrap();
    let verifier = P256Verifier::from(&EcdsaPublicKey::from_untagged_point(
        GenericArray::from_slice(TEST_VECTOR.pk),
    ));

    c.bench_function("ring: ECDSA (nistp256) verifier", move |b| {
        b.iter(|| verifier.verify_sha256(TEST_VECTOR.msg, &signature).unwrap())
    });
}

criterion_group! {
    name = ecdsa_p256;
    config = Criterion::default();
    targets = sign_ecdsa_p256, verify_ecdsa_p256
}

criterion_main!(ecdsa_p256);
