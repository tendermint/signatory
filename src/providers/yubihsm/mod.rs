//! yubihsm-rs provider

use std::sync::{Arc, Mutex};
use yubihsm::Session as YubiHSMSession;

mod ed25519;

use error::Error;
use self::ed25519::Ed25519Signer;

/// Identifiers for keys in the `YubiHSM`
pub type KeyId = u16;

/// End-to-end encrypted session with the `YubiHSM`
pub struct Session(Arc<Mutex<YubiHSMSession>>);

impl Session {
    /// Create a new session with the YubiHSM
    pub fn new(connector_url: &str, auth_key_id: KeyId, password: &str) -> Result<Self, Error> {
        let arc = Arc::new(Mutex::new(YubiHSMSession::create_from_password(
            connector_url,
            auth_key_id,
            password,
            true,
        ).map_err(|e| {
            err!(ProviderError, "{}", e)
        })?));

        Ok(Session(arc))
    }

    /// Create an Ed25519 signer which uses this session
    pub fn ed25519_signer(&self, signing_key_id: KeyId) -> Result<Ed25519Signer, Error> {
        Ed25519Signer::new(self, signing_key_id)
    }
}
