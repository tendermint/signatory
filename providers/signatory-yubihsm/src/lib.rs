//! yubihsm-rs provider: supports ECDSA (P-256, secp256k1) and Ed25519 signing
//!
//! `YubiHSM2` devices are relatively inexpensive hardware security modules
//! (HSMs) which natively implement many cryptographic primitives including
//! ECDSA and Ed25519, both of which are supported by this adapter.

#![crate_name = "signatory_yubihsm"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-yubihsm/0.9.0-alpha2"
)]

#[cfg(feature = "secp256k1")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "secp256k1")]
extern crate secp256k1;
pub extern crate signatory;
pub extern crate yubihsm;

#[macro_use]
mod error;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
mod session;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::EcdsaSigner;
#[cfg(feature = "ed25519")]
pub use self::ed25519::Ed25519Signer;
pub use self::session::Session;

/// Identifiers for keys in the `YubiHSM`
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct KeyId(pub yubihsm::ObjectId);

impl From<yubihsm::ObjectId> for KeyId {
    fn from(id: yubihsm::ObjectId) -> KeyId {
        KeyId(id)
    }
}
