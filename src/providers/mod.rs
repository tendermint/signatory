//! Providers which implement digital signature algorithms
//!
//! This is presently specialized to Ed25519. This API will need to be
//! redesigned in order to support e.g. ECDSA

/// curve25519-dalek software provider
#[cfg(feature = "dalek-provider")]
pub mod dalek;

/// `YubiHSM2` hardware provider
#[cfg(feature = "yubihsm-provider")]
pub mod yubihsm;

#[cfg(feature = "dalek-provider")]
pub use self::dalek::DalekSigner;

#[cfg(feature = "yubihsm-provider")]
pub use self::yubihsm::{YubiHSMSession, YubiHSMSigner};
