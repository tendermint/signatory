//! ECDSA signatures

/// ASN.1 DER signatures
pub(crate) mod asn1;

/// Fixed sized signatures
pub(crate) mod fixed;

/// Signature `r` and `s` values parsed as `ScalarPair`
#[cfg(feature = "encoding")]
pub(crate) mod scalars;

/// Marker trait for ECDSA signatures
pub trait Signature: crate::Signature {}
