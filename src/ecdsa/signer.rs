//! Trait for ECDSA signers

use generic_array::{typenum::U32, GenericArray};

use super::{curve::WeierstrassCurve, DERSignature, FixedSignature, PublicKey};
use error::Error;

/// ECDSA signer base trait
pub trait Signer<C: WeierstrassCurve>: Send + Sync {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<C>, Error>;
}

/// ECDSA signer which computes SHA-256 digests of messages and returns
/// ASN.1 DER-encoded signatures
pub trait SHA256DERSigner<C>: Signer<C>
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Compute an ASN.1 DER-encoded ECDSA signature for the SHA-256 digest
    /// of the given message.
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<C>, Error>;
}

/// ECDSA signer which computes SHA-256 digests of messages and returns
/// fixed-width encoded signatures
pub trait SHA256FixedSigner<C>: Signer<C>
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Compute a compact, fixed-width ECDSA signature for the SHA-256 digest
    /// of the given message.
    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature<C>, Error>;
}

/// Sign a raw digest the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message) returning an ASN.1 DER signature
pub trait RawDigestDERSigner<C>: Signer<C>
where
    C: WeierstrassCurve,
{
    /// Compute an ASN.1 DER encoded signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn sign_digest_der(
        &self,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
    ) -> Result<DERSignature<C>, Error>;
}

/// Sign a raw digest the same size as the curve's field (i.e. without first
/// computing a SHA-2 digest of the message) returning a fixed-width signature
pub trait RawDigestFixedSigner<C>: Signer<C>
where
    C: WeierstrassCurve,
{
    /// Compute a compact, fixed-width signature of a fixed-sized message
    /// whose length matches the size of the curve's field.
    fn sign_digest_fixed(
        &self,
        digest: &GenericArray<u8, C::PrivateScalarSize>,
    ) -> Result<FixedSignature<C>, Error>;
}
