//! ledger-tm provider: Ledger Tendermint Validator app (Ed25519 signatures for Amino votes)

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/iqlusioninc/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-ledger-tm/0.19.1"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

mod ledgertm;
mod signer;

pub use crate::signer::Ed25519LedgerTmAppSigner;
