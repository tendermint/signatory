//! Trait for ECDSA signers

use generic_array::GenericArray;

use error::Error;
#[cfg(feature = "std")]
use super::DERSignature;
use super::{PublicKey, RawSignature};
use super::curve::WeierstrassCurve;

/// Trait for ECDSA signers (object safe)
///
/// When using this trait, the message will first be hashed using the SHA-2
/// function whose digest size matches the size of the elliptic curve's field.
///
/// NOTE: Support is not (yet) provided for mixing and matching curve and
/// digest sizes. If you are interested in this, please open an issue.
pub trait Signer<C: WeierstrassCurve>: Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<C>, Error>;

    /// Compute a compact, fixed-width ECDSA signature for the SHA-256 digest
    /// of the given message.
    fn sign_sha2_raw(&self, msg: &[u8]) -> Result<RawSignature<C>, Error>;

    /// Compute an ASN.1 DER-encoded ECDSA signature for the SHA-256 digest
    /// of the given message.
    #[cfg(feature = "std")]
    fn sign_sha2_der(&self, msg: &[u8]) -> Result<DERSignature<C>, Error>;
}

/// Sign a raw message the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message)
pub trait FixedSizeInputSigner<C: WeierstrassCurve>: Sync {
    /// Compute a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn sign_fixed_raw(
        &self,
        msg: &GenericArray<u8, C::PrivateKeySize>,
    ) -> Result<RawSignature<C>, Error>;

    /// Compute an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    #[cfg(feature = "std")]
    fn sign_fixed_der(
        &self,
        msg: &GenericArray<u8, C::PrivateKeySize>,
    ) -> Result<DERSignature<C>, Error>;
}
