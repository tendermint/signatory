//! Signatory Ed25519 provider for *sodiumoxide*

#![crate_name = "signatory_sodiumoxide"]
#![crate_type = "lib"]
#![no_std]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-sodiumoxide/0.9.0-alpha1"
)]

#[cfg_attr(test, macro_use)]
extern crate signatory;
extern crate sodiumoxide;

use signatory::{
    ed25519::{Ed25519PublicKey, Ed25519Signature, FromSeed, Seed},
    error::{Error, ErrorKind},
    PublicKeyed, Signature, Signer, Verifier,
};
use sodiumoxide::crypto::sign::ed25519::{self as sodiumoxide_ed25519, SecretKey};

/// Ed25519 signature provider for *sodiumoxide*
pub struct Ed25519Signer {
    secret_key: SecretKey,
    public_key: Ed25519PublicKey,
}

impl FromSeed for Ed25519Signer {
    /// Create a new SodiumOxideSigner from an unexpanded seed value
    fn from_seed<S: Into<Seed>>(seed: S) -> Self {
        let sodiumoxide_seed = sodiumoxide_ed25519::Seed::from_slice(&seed.into().0[..]).unwrap();
        let (public_key, secret_key) = sodiumoxide_ed25519::keypair_from_seed(&sodiumoxide_seed);

        Self {
            secret_key,
            public_key: Ed25519PublicKey::from_bytes(&public_key.0).unwrap(),
        }
    }
}

impl PublicKeyed<Ed25519PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<Ed25519PublicKey, Error> {
        Ok(self.public_key)
    }
}

impl<'a> Signer<&'a [u8], Ed25519Signature> for Ed25519Signer {
    fn sign(&self, msg: &'a [u8]) -> Result<Ed25519Signature, Error> {
        let signature = sodiumoxide_ed25519::sign_detached(msg, &self.secret_key);
        Ok(Ed25519Signature::from_bytes(&signature.0[..]).unwrap())
    }
}

/// Ed25519 verifier for sodiumoxide
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519Verifier(sodiumoxide_ed25519::PublicKey);

impl<'a> From<&'a Ed25519PublicKey> for Ed25519Verifier {
    fn from(public_key: &'a Ed25519PublicKey) -> Self {
        Ed25519Verifier(sodiumoxide_ed25519::PublicKey::from_slice(public_key.as_bytes()).unwrap())
    }
}

impl<'a> Verifier<&'a [u8], Ed25519Signature> for Ed25519Verifier {
    fn verify(&self, msg: &'a [u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let sig = sodiumoxide_ed25519::Signature::from_slice(signature.as_ref()).unwrap();
        if sodiumoxide_ed25519::verify_detached(&sig, msg, &self.0) {
            Ok(())
        } else {
            Err(ErrorKind::SignatureInvalid.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
