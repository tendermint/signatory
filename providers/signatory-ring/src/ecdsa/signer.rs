//! Generic *ring* ECDSA signer

use core::marker::PhantomData;
use ring::{
    self,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
use signatory::{
    ecdsa::Signature,
    error::{Error, ErrorKind},
};
use untrusted;

/// Generic ECDSA signer which is wrapped with curve and signature-specific types
pub(super) struct EcdsaSigner<S: Signature> {
    /// *ring* ECDSA keypair
    keypair: EcdsaKeyPair,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Signature type produced by this signer
    signature: PhantomData<S>,
}

impl<S> EcdsaSigner<S>
where
    S: Signature,
{
    /// Create an ECDSA signer
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8_bytes: &[u8],
    ) -> Result<Self, Error> {
        let keypair = EcdsaKeyPair::from_pkcs8(alg, untrusted::Input::from(pkcs8_bytes))
            .map_err(|_| Error::from(ErrorKind::KeyInvalid))?;

        let csrng = SystemRandom::new();

        Ok(Self {
            keypair,
            csrng,
            signature: PhantomData,
        })
    }

    /// Get the public key for this ECDSA signer
    pub fn public_key(&self) -> &[u8] {
        self.keypair.public_key().as_ref()
    }

    /// Sign a message, returning the signature
    pub fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        let sig = self
            .keypair
            .sign(&self.csrng, untrusted::Input::from(msg))
            .map_err(|_| Error::from(ErrorKind::ProviderError))?;

        S::from_bytes(sig)
    }
}
