//! yubihsm-rs provider: supports ECDSA (P-256, secp256k1) and Ed25519 signing
//!
//! `YubiHSM2` devices are relatively inexpensive hardware security modules
//! (HSMs) which natively implement many cryptographic primitives including
//! ECDSA and Ed25519, both of which are supported by this adapter.

#![crate_name = "signatory_yubihsm"]
#![crate_type = "lib"]
#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/master/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-yubihsm/0.8.0"
)]

#[cfg(feature = "secp256k1")]
#[macro_use]
extern crate lazy_static;
#[cfg(feature = "secp256k1")]
extern crate secp256k1;
extern crate signatory;
extern crate yubihsm;

use std::sync::{Arc, Mutex};

#[macro_use]
mod error;

#[cfg(feature = "ecdsa")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "ecdsa")]
use self::ecdsa::EcdsaSigner;
#[cfg(feature = "ed25519")]
use self::ed25519::Ed25519Signer;
#[cfg(feature = "ecdsa")]
use signatory::curve::WeierstrassCurve;
use signatory::Error;

/// Identifiers for keys in the `YubiHSM`
pub type KeyId = u16;

/// HTTP sessions with `yubihsm-connector`
#[cfg(feature = "http")]
pub type HttpSession = Session<yubihsm::HttpAdapter>;

/// Direct USB sessions with the HSM using `libusb`
#[cfg(feature = "usb")]
pub type UsbSession = Session<yubihsm::UsbAdapter>;

/// End-to-end encrypted session with the `YubiHSM`
pub struct Session<A: yubihsm::Adapter>(Arc<Mutex<yubihsm::Session<A>>>);

impl<A: yubihsm::Adapter> Session<A> {
    /// Connect to the YubiHSM and open a new session
    pub fn create(
        config: A::Config,
        credentials: yubihsm::Credentials,
        reconnect: bool,
    ) -> Result<Self, Error> {
        yubihsm::Session::create(config, credentials, reconnect)
            .map(|s| Session(Arc::new(Mutex::new(s))))
            .map_err(|e| err!(ProviderError, "{}", e))
    }

    /// Initialize a new encrypted session, deferring actually establishing
    /// a session until `connect()` is called
    pub fn new(config: A::Config, credentials: yubihsm::Credentials) -> Result<Self, Error> {
        yubihsm::Session::new(config, credentials)
            .map(|s| Session(Arc::new(Mutex::new(s))))
            .map_err(|e| err!(ProviderError, "{}", e))
    }

    /// Connect to the YubiHSM
    pub fn open(&mut self) -> Result<(), Error> {
        let mut session = self.0.lock().unwrap();
        if let Err(e) = session.open() {
            fail!(ProviderError, "{}", e);
        }
        Ok(())
    }

    /// Do we currently have an open session with the HSM?
    pub fn is_open(&self) -> bool {
        let session = self.0.lock().unwrap();
        session.is_open()
    }

    /// Get the current session ID
    #[inline]
    pub fn id(&self) -> Option<yubihsm::SessionId> {
        let session = self.0.lock().unwrap();
        session.id()
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
    pub fn ecdsa_signer<C>(&self, signing_key_id: KeyId) -> Result<EcdsaSigner<A, C>, Error>
    where
        C: WeierstrassCurve,
    {
        EcdsaSigner::new(self, signing_key_id)
    }

    /// Create an Ed25519 signer which uses this session
    #[cfg(feature = "ed25519")]
    pub fn ed25519_signer(&self, signing_key_id: KeyId) -> Result<Ed25519Signer<A>, Error> {
        Ed25519Signer::new(self, signing_key_id)
    }
}
