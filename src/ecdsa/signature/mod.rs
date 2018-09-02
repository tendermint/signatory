//! ECDSA signatures

/// ASN.1 DER signatures
pub(crate) mod asn1;

/// Fixed sized signatures
pub(crate) mod fixed;

/// `IntPair`: `r` and `s` integer pair of which ECDSA signatures are comprised
pub(crate) mod pair;

use Signature;

/// Marker trait for ECDSA signatures
pub trait EcdsaSignature: Signature {}
