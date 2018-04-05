//! Providers which implement digital signature algorithms
//!
//! This is presently specialized to Ed25519. This API will need to be
//! redesigned in order to support e.g. ECDSA

/// ed25519-dalek software provider
#[cfg(feature = "dalek-provider")]
pub mod dalek;

/// *ring* software provider
#[cfg(feature = "ring-provider")]
pub mod ring;

/// sodiumoxide (i.e. libsodium) software preovider
#[cfg(feature = "sodiumoxide-provider")]
pub mod sodiumoxide;

/// `YubiHSM2` hardware provider
#[cfg(feature = "yubihsm-provider")]
pub mod yubihsm;

#[cfg(feature = "dalek-provider")]
pub use self::dalek::{DalekSigner, DalekVerifier};

#[cfg(feature = "ring-provider")]
pub use self::ring::{RingSigner, RingVerifier};

#[cfg(feature = "sodiumoxide-provider")]
pub use self::sodiumoxide::{SodiumOxideSigner, SodiumOxideVerifier};

#[cfg(feature = "yubihsm-provider")]
pub use self::yubihsm::{YubiHSMSession, YubiHSMSigner};
