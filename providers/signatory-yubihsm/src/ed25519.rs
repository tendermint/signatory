//! Digital signature (i.e. Ed25519) provider for `YubiHSM2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM2`, then
//! call the appropriate signer methods to obtain signers.

use signatory::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    error::{Error, ErrorKind},
    PublicKeyed, Signature, Signer,
};
use std::sync::{Arc, Mutex};
use yubihsm;

use super::{KeyId, Session};

/// Ed25519 signature provider for yubihsm-client
pub struct Ed25519Signer {
    /// Session with the YubiHSM
    hsm: Arc<Mutex<yubihsm::Client>>,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: KeyId,
}

impl Ed25519Signer {
    /// Create a new YubiHSM-backed Ed25519 signer
    pub(crate) fn new(session: &Session, signing_key_id: KeyId) -> Result<Self, Error> {
        let signer = Self {
            hsm: session.0.clone(),
            signing_key_id,
        };

        // Ensure the signing_key_id slot contains a valid Ed25519 public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl PublicKeyed<Ed25519PublicKey> for Ed25519Signer {
    fn public_key(&self) -> Result<Ed25519PublicKey, Error> {
        let mut hsm = self.hsm.lock().unwrap();

        let pubkey = hsm
            .get_pubkey(self.signing_key_id.0)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if pubkey.algorithm != yubihsm::AsymmetricAlg::Ed25519 {
            return Err(ErrorKind::KeyInvalid.into());
        }

        Ok(Ed25519PublicKey::from_bytes(pubkey.as_ref()).unwrap())
    }
}

impl Signer<Ed25519Signature> for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, Error> {
        let mut hsm = self.hsm.lock().unwrap();

        let signature = hsm
            .sign_ed25519(self.signing_key_id.0, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(Ed25519Signature::from_bytes(signature.as_ref()).unwrap())
    }
}
