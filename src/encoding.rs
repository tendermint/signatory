//! Support for encoding and decoding serialization formats (hex and Base64)
//! with implementations that do not branch on potentially secret data, such
//! as cryptographic keys.

#[macro_use]
mod macros;

pub use subtle_encoding::{Base64, Hex, Identity};
mod decode;
#[cfg(feature = "alloc")]
mod encode;
pub mod error;
#[cfg(feature = "pkcs8")]
pub mod pkcs8;

#[cfg(feature = "alloc")]
pub use self::encode::Encode;
#[cfg(feature = "pkcs8")]
pub use self::pkcs8::FromPkcs8;
pub use self::{decode::Decode, error::Error};

/// Mode to use for newly created files
#[cfg(all(unix, feature = "std"))]
pub const FILE_MODE: u32 = 0o600;
