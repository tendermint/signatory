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

extern crate ed25519_dalek;
extern crate sha2;
#[cfg_attr(test, macro_use)]
extern crate signatory;

use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Keypair, SecretKey};
use sha2::Sha512;

use signatory::{
    ed25519::{FromSeed, PublicKey, Seed, Signature, Signer, Verifier},
    error::{Error, ErrorKind},
};

/// Ed25519 signature provider for ed25519-dalek
pub struct Ed25519Signer(Keypair);

impl FromSeed for Ed25519Signer {
    /// Create a new DalekSigner from an unexpanded seed value
    fn from_seed<S: Into<Seed>>(seed: S) -> Self {
        let sk = SecretKey::from_bytes(&seed.into().as_secret_slice()).unwrap();
        let pk = DalekPublicKey::from_secret::<Sha512>(&sk);

        Ed25519Signer(Keypair {
            secret: sk,
            public: pk,
        })
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(self.0.public.as_bytes()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        Ok(Signature::from_bytes(&self.0.sign::<Sha512>(msg).to_bytes()[..]).unwrap())
    }
}

/// Ed25519 verifier provider for ed25519-dalek
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(key: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), Error> {
        let pk = DalekPublicKey::from_bytes(key.as_ref()).unwrap();
        let sig = DalekSignature::from_bytes(signature.as_ref()).unwrap();

        pk.verify::<Sha512>(msg, &sig)
            .map_err(|_| ErrorKind::SignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519Signer, Ed25519Verifier};
    ed25519_tests!(Ed25519Signer, Ed25519Verifier);
}
