//! Signatory Ed25519 provider for *sodiumoxide*

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/iqlusioninc/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-sodiumoxide/0.19.0"
)]

#[cfg(test)]
#[macro_use]
extern crate signatory;

use signatory::{
    ed25519,
    public_key::PublicKeyed,
    signature::{Error, Signature, Signer, Verifier},
};
use sodiumoxide::crypto::sign::ed25519::{self as sodiumoxide_ed25519, SecretKey};

/// Ed25519 signature provider for *sodiumoxide*
pub struct Ed25519Signer {
    secret_key: SecretKey,
    public_key: ed25519::PublicKey,
}

impl<'a> From<&'a ed25519::Seed> for Ed25519Signer {
    /// Create a new SodiumOxideSigner from an unexpanded seed value
    fn from(seed: &'a ed25519::Seed) -> Self {
        let sodiumoxide_seed =
            sodiumoxide_ed25519::Seed::from_slice(seed.as_secret_slice()).unwrap();
        let (public_key, secret_key) = sodiumoxide_ed25519::keypair_from_seed(&sodiumoxide_seed);

        Self {
            secret_key,
            public_key: ed25519::PublicKey::from_bytes(&public_key.0).unwrap(),
        }
    }
}

impl PublicKeyed<ed25519::PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<ed25519::PublicKey, Error> {
        Ok(self.public_key)
    }
}

impl Signer<ed25519::Signature> for Ed25519Signer {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, Error> {
        let signature = sodiumoxide_ed25519::sign_detached(msg, &self.secret_key);
        Ok(Signature::from_bytes(&signature.0[..]).unwrap())
    }
}

/// Ed25519 verifier for sodiumoxide
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Verifier(sodiumoxide_ed25519::PublicKey);

impl<'a> From<&'a ed25519::PublicKey> for Ed25519Verifier {
    fn from(public_key: &'a ed25519::PublicKey) -> Self {
        Ed25519Verifier(sodiumoxide_ed25519::PublicKey::from_slice(public_key.as_bytes()).unwrap())
    }
}

impl Verifier<ed25519::Signature> for Ed25519Verifier {
    fn verify(&self, msg: &[u8], signature: &ed25519::Signature) -> Result<(), Error> {
        let sig = sodiumoxide_ed25519::Signature::from_slice(signature.as_ref()).unwrap();
        if sodiumoxide_ed25519::verify_detached(&sig, msg, &self.0) {
            Ok(())
        } else {
            Err(Error::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
