//! Types for use with the `digest` crate

// Re-export the `digest` crate if enabled
extern crate digest as digest_crate;
pub use self::digest_crate::*;

#[cfg(feature = "generic-array")]
use generic_array::GenericArray;

/// The output of a digest function (i.e. a digest as a byte array)
#[cfg(feature = "generic-array")]
pub type DigestOutput<D> = GenericArray<u8, <D as FixedOutput>::OutputSize>;
