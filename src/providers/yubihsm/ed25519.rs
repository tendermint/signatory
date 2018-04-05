//! Digital signature (i.e. Ed25519) provider for `YubiHSM2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM2`, then
//! call the appropriate signer methods to obtain signers.

use std::sync::{Arc, Mutex};
use yubihsm::{Algorithm, Connector, DefaultConnector};
use yubihsm::Session as YubiHSMSession;

use error::{Error, ErrorKind};
use ed25519::{PublicKey, Signature, Signer};
use super::{KeyId, Session};

/// Ed25519 signature provider for yubihsm-client
pub struct Ed25519Signer<C = DefaultConnector>
where
    C: Connector,
{
    /// Session with the YubiHSM
    session: Arc<Mutex<YubiHSMSession<C>>>,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: KeyId,
}

impl Ed25519Signer<DefaultConnector> {
    /// Create a new YubiHSM-backed Ed25519 signer
    pub fn new(session: &Session, signing_key_id: KeyId) -> Result<Self, Error> {
        let signer = Self {
            session: session.0.clone(),
            signing_key_id,
        };

        // Ensure the signing_key_id slot contains a valid Ed25519 public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl<C: Connector> Signer for Ed25519Signer<C> {
    fn public_key(&self) -> Result<PublicKey, Error> {
        let mut session = self.session.lock().unwrap();

        let pubkey_response = session
            .get_pubkey(self.signing_key_id)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if pubkey_response.algorithm != Algorithm::EC_ED25519 {
            return Err(ErrorKind::KeyInvalid.into());
        }

        Ok(PublicKey::from_bytes(pubkey_response.data.as_ref()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let mut session = self.session.lock().unwrap();

        let response = session
            .sign_data_eddsa(self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(Signature::from_bytes(response.signature.as_ref()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use yubihsm::{Algorithm, Capabilities, Domains, ObjectType};
    #[cfg(not(feature = "yubihsm-mockhsm"))]
    use yubihsm::Session;
    #[cfg(feature = "yubihsm-mockhsm")]
    use yubihsm::mockhsm::MockHSM;

    use super::{Ed25519Signer, KeyId, Signer};

    /// Default addr/port for yubihsm-connector
    #[cfg(not(feature = "yubihsm-mockhsm"))]
    const DEFAULT_CONNECTOR_ADDR: &str = "http://127.0.0.1:12345";

    /// Default authentication key identifier
    const DEFAULT_AUTH_KEY_ID: KeyId = 1;

    /// Default YubiHSM2 password
    const DEFAULT_PASSWORD: &str = "password";

    /// Key ID to use for test key
    const TEST_SIGNING_KEY_ID: KeyId = 123;

    /// Domain IDs for test key
    const TEST_SIGNING_KEY_DOMAINS: Domains = Domains::DOMAIN_1;

    /// Capabilities for test key
    const TEST_SIGNING_KEY_CAPABILITIES: Capabilities = Capabilities::ASYMMETRIC_SIGN_EDDSA;

    /// Label for test key
    const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

    /// Example message to sign
    const TEST_MESSAGE: &[u8] = b"The Edwards-curve Digital Signature Algorithm (EdDSA) is a \
        variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

    // We need dalek to actually verify the signature
    #[cfg(feature = "dalek-provider")]
    #[test]
    fn generates_signature_verifiable_by_dalek() {
        #[cfg(not(feature = "yubihsm-mockhsm"))]
        let session = Arc::new(Mutex::new(
            Session::create_from_password(
                DEFAULT_CONNECTOR_ADDR,
                DEFAULT_AUTH_KEY_ID,
                DEFAULT_PASSWORD,
                true,
            ).unwrap_or_else(|err| panic!("error creating session: {}", err)),
        ));

        #[cfg(feature = "yubihsm-mockhsm")]
        let session = Arc::new(Mutex::new(
            MockHSM::create_session(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
                .unwrap_or_else(|err| panic!("error creating session: {:?}", err)),
        ));

        {
            let mut s = session.lock().unwrap();

            // Delete the key in TEST_KEY_ID slot it exists
            // Ignore errors since the object may not exist yet
            let _ = s.delete_object(TEST_SIGNING_KEY_ID, ObjectType::Asymmetric);

            // Create a new key for testing
            s.generate_asymmetric_key(
                TEST_SIGNING_KEY_ID,
                TEST_SIGNING_KEY_LABEL.into(),
                TEST_SIGNING_KEY_DOMAINS,
                TEST_SIGNING_KEY_CAPABILITIES,
                Algorithm::EC_ED25519,
            ).unwrap();
        }

        let signer = Ed25519Signer {
            session: session,
            signing_key_id: TEST_SIGNING_KEY_ID,
        };

        let public_key = signer.public_key().unwrap();
        let signature = signer.sign(TEST_MESSAGE).unwrap();

        assert!(public_key.verify(TEST_MESSAGE, &signature).is_ok());
    }
}
