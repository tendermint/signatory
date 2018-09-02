//! Signatory Ed25519 provider for ed25519-dalek

#![crate_name = "signatory_dalek"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-dalek/0.8.0"
)]

extern crate digest;
extern crate ed25519_dalek;
extern crate sha2;
#[cfg_attr(test, macro_use)]
extern crate signatory;

use digest::Digest;
use ed25519_dalek::{Keypair, SecretKey};
use sha2::Sha512;

use signatory::{
    ed25519::{Ed25519Signature, FromSeed, PublicKey, Seed},
    error::{Error, ErrorKind},
    generic_array::typenum::U64,
    DigestSigner, DigestVerifier, PublicKeyed, Signature, Signer, Verifier,
};

/// Ed25519 signature provider for ed25519-dalek
pub struct Ed25519Signer(Keypair);

impl FromSeed for Ed25519Signer {
    /// Create a new DalekSigner from an unexpanded seed value
    fn from_seed<S: Into<Seed>>(seed: S) -> Self {
        let sk = SecretKey::from_bytes(&seed.into().as_secret_slice()).unwrap();
        let pk = ed25519_dalek::PublicKey::from_secret::<Sha512>(&sk);

        Ed25519Signer(Keypair {
            secret: sk,
            public: pk,
        })
    }
}

impl PublicKeyed<PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public.as_bytes()).unwrap())
    }
}

impl<'a> Signer<&'a [u8], Ed25519Signature> for Ed25519Signer {
    fn sign(&self, msg: &'a [u8]) -> Result<Ed25519Signature, Error> {
        Ok(Ed25519Signature::from_bytes(&self.0.sign::<Sha512>(msg).to_bytes()[..]).unwrap())
    }
}

// TODO: test vectors!
impl<D> DigestSigner<D, Ed25519Signature> for Ed25519Signer
where
    D: Digest<OutputSize = U64> + Default,
{
    fn sign_digest(&self, digest: D) -> Result<Ed25519Signature, Error> {
        // TODO: context support
        let context: Option<&'static [u8]> = None;

        let signature = Ed25519Signature::from_bytes(
            &self.0.sign_prehashed(digest, context).to_bytes()[..],
        ).unwrap();

        Ok(signature)
    }
}

/// Ed25519 verifier provider for ed25519-dalek
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Verifier(ed25519_dalek::PublicKey);

impl<'a> From<&'a PublicKey> for Ed25519Verifier {
    fn from(public_key: &'a PublicKey) -> Self {
        Ed25519Verifier(ed25519_dalek::PublicKey::from_bytes(public_key.as_ref()).unwrap())
    }
}

impl<'a> Verifier<&'a [u8], Ed25519Signature> for Ed25519Verifier {
    fn verify(&self, msg: &'a [u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_ref()).unwrap();
        self.0
            .verify::<Sha512>(msg, &sig)
            .map_err(|_| ErrorKind::SignatureInvalid.into())
    }
}

// TODO: test vectors!
impl<D> DigestVerifier<D, Ed25519Signature> for Ed25519Verifier
where
    D: Digest<OutputSize = U64> + Default,
{
    fn verify_digest(&self, digest: D, signature: &Ed25519Signature) -> Result<(), Error> {
        // TODO: context support
        let context: Option<&'static [u8]> = None;
        let sig = ed25519_dalek::Signature::from_bytes(signature.as_ref()).unwrap();
        self.0
            .verify_prehashed(digest, context, &sig)
            .map_err(|_| ErrorKind::SignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
