//! Generic wrapper for *ring*'s ECDSA signing functionality

use core::marker::PhantomData;
use ring::{
    self,
    rand::SystemRandom,
    signature::{KeyPair, SigningAlgorithm},
};
use signatory::{ecdsa::EcdsaSignature, error::Error};
use untrusted;

/// Generic ECDSA signer which is wrapped with curve and signature-specific types
pub(super) struct EcdsaSigner<S: EcdsaSignature> {
    /// *ring* ECDSA keypair
    keypair: KeyPair,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Signature type produced by this signer
    signature: PhantomData<S>,
}

impl<S> EcdsaSigner<S>
where
    S: EcdsaSignature,
{
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    pub(super) fn from_pkcs8(
        alg: &'static SigningAlgorithm,
        pkcs8_bytes: &[u8],
    ) -> Result<Self, Error> {
        let keypair =
            ring::signature::key_pair_from_pkcs8(alg, untrusted::Input::from(pkcs8_bytes))
                .map_err(|_| err!(KeyInvalid, "invalid PKCS#8 key"))?;

        let csrng = SystemRandom::new();

        Ok(Self {
            keypair,
            csrng,
            signature: PhantomData,
        })
    }

    /// Sign a message, returning a *ring* `Signature` type
    pub(super) fn sign(&self, msg: &[u8]) -> Result<ring::signature::Signature, Error> {
        ring::signature::sign(&self.keypair, &self.csrng, untrusted::Input::from(msg))
            .map_err(|_| err!(ProviderError, "signing failure"))
    }
}
