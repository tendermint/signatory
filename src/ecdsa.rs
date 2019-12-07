//! The Elliptic Curve Digital Signature Algorithm (ECDSA) as specified in
//! FIPS 186-4 (Digital Signature Standard)

use core::ops::Add;
use ecdsa::curve::{CompressedPointSize, UncompressedPointSize};
use generic_array::{typenum::U1, ArrayLength};

// Use public and secret key types from the ecdsa crate
// TODO(tarcieri): re-export these in a more usable manner
pub use ::ecdsa::{PublicKey, SecretKey};

// Use signature and curve types from the `ecdsa` crate
pub use ::ecdsa::{curve, generic_array, Asn1Signature, Curve, FixedSignature};

#[cfg(feature = "test-vectors")]
pub use ::ecdsa::test_vectors;

impl<C> crate::public_key::PublicKey for PublicKey<C>
where
    C: Curve,
    <C::ScalarSize as Add>::Output: Add<U1>,
    CompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
    UncompressedPointSize<C::ScalarSize>: ArrayLength<u8>,
{
}
