//! ed25519-ledger-tm provider benchmarks

#![allow(unused_imports)]
#![deny(warnings)]

#[macro_use]
extern crate criterion;
use signatory;

use criterion::Criterion;
use signatory::{ed25519, Signature, Verifier};
use signatory_ledger_tm::Ed25519LedgerTmAppSigner;

fn pubkey_ed25519(c: &mut Criterion) {
    let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

    c.bench_function("ledger-tm: Ed25519 get public key", move |b| {
        b.iter(|| signatory::public_key(&signer).unwrap())
    });
}

criterion_group! {
    name = ed25519;
    config = Criterion::default();
    targets = pubkey_ed25519
}

criterion_main!(ed25519);
