//! yubihsm-rs provider: supports ECDSA (P-256, secp256k1) and Ed25519 signing
//!
//! `YubiHSM2` devices are relatively inexpensive hardware security modules
//! (HSMs) which natively implement many cryptographic primitives including
//! ECDSA and Ed25519, both of which are supported by this adapter.

use std::sync::{Arc, Mutex};
use yubihsm_crate;
pub use yubihsm_crate::connector::HttpConfig as Config;

mod ecdsa;
mod ed25519;

use self::ecdsa::ECDSASigner;
use self::ed25519::Ed25519Signer;
use ecdsa::curve::WeierstrassCurve;
use error::Error;

/// Identifiers for keys in the `YubiHSM`
pub type KeyId = u16;

/// End-to-end encrypted session with the `YubiHSM`
pub struct Session(Arc<Mutex<yubihsm_crate::Session>>);

impl Session {
    /// Create a new YubiHSM session from the given password
    pub fn create_from_password(
        config: Config,
        auth_key_id: KeyId,
        password: &str,
    ) -> Result<Self, Error> {
        let auth_key = yubihsm_crate::AuthKey::derive_from_password(password.as_bytes());

        Self::new(config, auth_key_id, auth_key)
    }

    /// Create a new session with the YubiHSM
    pub fn new<K: Into<yubihsm_crate::AuthKey>>(
        config: Config,
        auth_key_id: KeyId,
        auth_key: K,
    ) -> Result<Self, Error> {
        let session = yubihsm_crate::Session::create(config, auth_key_id, auth_key.into(), true)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(Session(Arc::new(Mutex::new(session))))
    }

    /// Create an ECDSA signer which uses this session. You will need to supply
    /// an elliptic curve to use when creating a signer:
    ///
    /// ```rust,ignore
    /// use signatory::ecdsa::{curve::NISTP256, signer::SHA256DERSigner};
    /// use signatory::providers::yubihsm;
    ///
    /// let session = yubihsm::Session::create_from_password(
    ///     yubihsm::Config::default(),
    ///     1,
    ///     "password"
    /// ).unwrap();
    ///
    /// // Note: You'll need to create a NIST P-256 key in slot `123` first.
    /// // Run the following from yubihsm-shell:
    /// // `generate asymmetric 0 123 p256_test_key 1 asymmetric_sign_ecdsa ecp256`
    /// let key_id = 123;
    ///
    /// // This will return an error unless there is already a NIST P-256 key
    /// // in slot 123
    /// let signer = session.ecdsa_signer::<NISTP256>(key_id).unwrap();
    ///
    /// let message = b"Hello, world!";
    /// let signature = signer.sign_sha256_der(message).unwrap();
    /// ```
    ///
    /// Supported elliptic curves are:
    ///
    /// * `signatory::ecdsa::curve::NISTP256`: NIST P-256 elliptic curve,
    ///   a.k.a. prime256v1 or secp256r1
    /// * `signatory::ecdsa::curve::Secp256k1`: secp256k1 elliptic curve
    ///   (used by Bitcoin)
    pub fn ecdsa_signer<C>(&self, signing_key_id: KeyId) -> Result<ECDSASigner<C>, Error>
    where
        C: WeierstrassCurve,
    {
        ECDSASigner::new(self, signing_key_id)
    }

    /// Create an Ed25519 signer which uses this session
    pub fn ed25519_signer(&self, signing_key_id: KeyId) -> Result<Ed25519Signer, Error> {
        Ed25519Signer::new(self, signing_key_id)
    }
}
