//! Providers are Signatory's plugins/adapters which provide a common
//! API to digital signature functionality.

#[cfg(feature = "dalek-provider")]
pub mod dalek;

#[cfg(feature = "ring-provider")]
pub mod ring;

#[cfg(feature = "sodiumoxide-provider")]
pub mod sodiumoxide;

#[cfg(feature = "yubihsm-provider")]
pub mod yubihsm;
