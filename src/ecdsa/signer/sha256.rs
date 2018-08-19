#[cfg(
    all(
        feature = "digest",
        feature = "sha2",
        not(feature = "yubihsm-mockhsm")
    )
)]
use digest::Input;
use generic_array::typenum::U32;
#[cfg(
    all(
        feature = "digest",
        feature = "sha2",
        not(feature = "yubihsm-mockhsm")
    )
)]
use sha2::Sha256;

#[cfg(
    all(
        feature = "digest",
        feature = "sha2",
        not(feature = "yubihsm-mockhsm")
    )
)]
use super::DigestSigner;
use super::Signer;
use ecdsa::{curve::WeierstrassCurve, DERSignature, FixedSignature};
use error::Error;

/// ECDSA signer which computes SHA-256 digests of messages
pub trait SHA256Signer<C>: Signer<C>
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Compute an ASN.1 DER-encoded ECDSA signature for the SHA-256 digest
    /// of the given message.
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<C>, Error> {
        Ok(DERSignature::from(&self.sign_sha256_fixed(msg)?))
    }

    /// Compute a compact, fixed-width ECDSA signature for the SHA-256 digest
    /// of the given message.
    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature<C>, Error> {
        Ok(FixedSignature::from(&self.sign_sha256_der(msg)?))
    }
}

// TODO: remove hacks around yubihsm-mockhsm
#[cfg(
    all(
        feature = "digest",
        feature = "sha2",
        not(feature = "yubihsm-mockhsm")
    )
)]
impl<C, S> SHA256Signer<C> for S
where
    C: WeierstrassCurve<PrivateScalarSize = U32>,
    S: DigestSigner<C, Sha256>,
{
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<C>, Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        self.sign_digest_der(sha256)
    }

    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature<C>, Error> {
        let mut sha256 = Sha256::default();
        sha256.process(msg);
        self.sign_digest_fixed(sha256)
    }
}
