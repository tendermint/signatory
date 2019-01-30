use signatory::{curve::WeierstrassCurve, Error};
use std::sync::{Arc, Mutex};
use yubihsm;

use super::KeyId;
use crate::ecdsa::EcdsaSigner;
use crate::ed25519::Ed25519Signer;

/// End-to-end encrypted session with the `YubiHSM`
pub struct Session(pub(super) Arc<Mutex<yubihsm::Client>>);

impl Session {
    /// Connect to the YubiHSM and open a new session
    pub fn create<C>(connector: C, credentials: yubihsm::Credentials) -> Result<Self, Error>
    where
        C: Into<Box<yubihsm::Connector>>,
    {
        let mut session = Self::new(connector, credentials)?;
        session.open()?;
        Ok(session)
    }

    /// Initialize a new encrypted session, deferring actually establishing
    /// a session until `connect()` is called
    pub fn new<C>(connector: C, credentials: yubihsm::Credentials) -> Result<Self, Error>
    where
        C: Into<Box<yubihsm::Connector>>,
    {
        yubihsm::Client::create(connector, credentials)
            .map(|c| Session(Arc::new(Mutex::new(c))))
            .map_err(|e| err!(ProviderError, "{}", e))
    }

    /// Connect to the YubiHSM
    pub fn open(&mut self) -> Result<(), Error> {
        let mut hsm = self.0.lock().unwrap();

        if let Err(e) = hsm.connect() {
            fail!(ProviderError, "{}", e);
        }

        Ok(())
    }

    /// Do we currently have an open session with the HSM?
    pub fn is_open(&self) -> bool {
        let hsm = self.0.lock().unwrap();
        hsm.is_connected()
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> Option<yubihsm::SessionId> {
        let mut hsm = self.0.lock().unwrap();
        hsm.session().map(|s| s.id()).ok()
    }

    /// Get the underlying `yubihsm::Client` object
    pub fn client(&self) -> Arc<Mutex<yubihsm::Client>> {
        self.0.clone()
    }

    /// Create an ECDSA signer which uses this session. You will need to supply
    /// an elliptic curve to use when creating a signer:
    ///
    /// ```rust,ignore
    /// extern crate signatory;
    /// extern crate signatory_yubihsm;
    ///
    /// use signatory::{curve::NISTP256, ecdsa::signer::SHA256Signer};
    /// use signatory_yubihsm::Session;
    ///
    /// // Create a YubiHSM2 session using the default configuration
    /// // WARNING: Don't use this in production!!!
    /// let session = Session::create_from_password(
    ///     Default::default(),
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
    /// * `signatory::curve::NISTP256`: NIST P-256 elliptic curve,
    ///   a.k.a. prime256v1 or secp256r1
    /// * `signatory::curve::Secp256k1`: secp256k1 elliptic curve
    ///   (used by Bitcoin)
    #[cfg(feature = "ecdsa")]
    pub fn ecdsa_signer<C>(&self, signing_key_id: KeyId) -> Result<EcdsaSigner<C>, Error>
    where
        C: WeierstrassCurve,
    {
        EcdsaSigner::create(self, signing_key_id)
    }

    /// Create an Ed25519 signer which uses this session
    #[cfg(feature = "ed25519")]
    pub fn ed25519_signer(&self, signing_key_id: KeyId) -> Result<Ed25519Signer, Error> {
        Ed25519Signer::create(self, signing_key_id)
    }
}
