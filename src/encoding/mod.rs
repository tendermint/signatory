//! Support for encoding and decoding serialization formats (hex and Base64)
//! with implementations that do not branch on potentially secret data, such
//! as cryptographic keys.

#[macro_use]
mod macros;

pub use subtle_encoding::{Base64, Hex, Identity};
#[cfg(feature = "ecdsa")]
pub(crate) mod asn1;
mod decode;
#[cfg(feature = "alloc")]
mod encode;
#[cfg(feature = "pkcs8")]
pub mod pkcs8;

pub use self::decode::Decode;
#[cfg(feature = "alloc")]
pub use self::encode::Encode;
#[cfg(feature = "pkcs8")]
pub use self::pkcs8::FromPkcs8;

/// Mode to use for newly created files
#[cfg(unix)]
pub const FILE_MODE: u32 = 0o600;
