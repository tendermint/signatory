//! Generic *ring* ECDSA signer

use core::marker::PhantomData;
use ring::{
    self,
    rand::SystemRandom,
    signature::{KeyPair, SigningAlgorithm},
};
use signatory::{
    curve::WeierstrassCurve,
    ecdsa::{EcdsaPublicKey, EcdsaSignature},
    error::{Error, ErrorKind},
    generic_array::{typenum::Unsigned, GenericArray},
};
use untrusted;

/// Generic ECDSA signer which is wrapped with curve and signature-specific types
pub struct EcdsaSigner<C: WeierstrassCurve, S: EcdsaSignature> {
    /// *ring* ECDSA keypair
    keypair: KeyPair,

    /// ECDSA public key for this signer
    // *ring* does not presently keep a copy of this.
    // See https://github.com/briansmith/ring/issues/672#issuecomment-404669397
    pub(super) public_key: EcdsaPublicKey<C>,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Signature type produced by this signer
    signature: PhantomData<S>,
}

impl<C, S> EcdsaSigner<C, S>
where
    C: WeierstrassCurve,
    S: EcdsaSignature,
{
    /// Create an ECDSA signer and public key from a PKCS#8
    pub(super) fn new(alg: &'static SigningAlgorithm, pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let keypair =
            ring::signature::key_pair_from_pkcs8(alg, untrusted::Input::from(pkcs8_bytes))
                .map_err(|_| Error::from(ErrorKind::KeyInvalid))?;

        // TODO: less hokey way of parsing the public key/point from the PKCS#8 file?
        let pubkey_bytes_pos = pkcs8_bytes
            .len()
            .checked_sub(<C as WeierstrassCurve>::UntaggedPointSize::to_usize())
            .unwrap();

        let public_key = EcdsaPublicKey::from_untagged_point(&GenericArray::from_slice(
            &pkcs8_bytes[pubkey_bytes_pos..],
        ));

        let csrng = SystemRandom::new();

        Ok(Self {
            keypair,
            public_key,
            csrng,
            signature: PhantomData,
        })
    }

    /// Sign a message, returning the signature
    pub(super) fn sign(&self, msg: &[u8]) -> Result<S, Error> {
        let sig = ring::signature::sign(&self.keypair, &self.csrng, untrusted::Input::from(msg))
            .map_err(|_| Error::from(ErrorKind::ProviderError))?;

        S::from_bytes(sig)
    }
}
