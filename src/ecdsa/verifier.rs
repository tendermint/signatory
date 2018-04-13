//! Trait for ECDSA verifiers

use core::fmt::Debug;
use core::hash::Hash;
use core::marker::PhantomData;
use generic_array::GenericArray;

use error::Error;
#[cfg(feature = "std")]
use super::DERSignature;
use super::{PublicKey, RawSignature};
use super::curve::WeierstrassCurve;

/// Verifier for ECDSA signatures which first hashes the input message using
/// the SHA-2 function whose digest matches the size of the elliptic curve's
/// field.
///
/// NOTE: Support is not (yet) provided for mixing and matching curve and
/// digest sizes. If you are interested in this, please open an issue.
pub trait Verifier<C>: Clone + Debug + Hash + Eq + PartialEq + Send + Sync
where
    C: WeierstrassCurve,
{
    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_sha2_raw_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &RawSignature<C>,
    ) -> Result<(), Error>;

    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    #[cfg(feature = "std")]
    fn verify_sha2_der_signature(
        key: &PublicKey<C>,
        msg: &[u8],
        signature: &DERSignature<C>,
    ) -> Result<(), Error>;
}

/// Verify a raw message the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message)
pub trait FixedSizeInputVerifier<C: WeierstrassCurve>: Send + Sync {
    /// Verify a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn verify_fixed_raw_signature(
        key: &PublicKey<C>,
        msg: &GenericArray<u8, C::PrivateKeySize>,
        signature: &RawSignature<C>,
    ) -> Result<(), Error>;

    /// Verify an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    #[cfg(feature = "std")]
    fn verify_fixed_der_signature(
        key: &PublicKey<C>,
        msg: &GenericArray<u8, C::PrivateKeySize>,
        signature: &DERSignature<C>,
    ) -> Result<(), Error>;
}

/// A panicking verifier we can use as the default if no other verifiers are available
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PanickingVerifier<C: WeierstrassCurve> {
    c: PhantomData<C>,
}

#[allow(dead_code)]
impl<C: WeierstrassCurve> Verifier<C> for PanickingVerifier<C> {
    fn verify_sha2_raw_signature(
        _key: &PublicKey<C>,
        _msg: &[u8],
        _signature: &RawSignature<C>,
    ) -> Result<(), Error> {
        panic!("no default provider available for {:?} ECDSA", C::default());
    }

    #[cfg(feature = "std")]
    fn verify_sha2_der_signature(
        _key: &PublicKey<C>,
        _msg: &[u8],
        _signature: &DERSignature<C>,
    ) -> Result<(), Error> {
        panic!("no default provider available for {:?} ECDSA", C::default());
    }
}
