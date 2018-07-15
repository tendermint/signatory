//! Digital signature (i.e. Ed25519) provider for `YubiHSM2` devices
//!
//! To use this provider, first establish a session with the `YubiHSM2`, then
//! call the appropriate signer methods to obtain signers.

use std::sync::{Arc, Mutex};
use yubihsm::Session as YubiHSMSession;
use yubihsm::{self, AsymmetricAlgorithm, Connector, HttpConnector};

use super::{KeyId, Session};
use ed25519::{PublicKey, Signature, Signer};
use error::{Error, ErrorKind};

/// Ed25519 signature provider for yubihsm-client
pub struct Ed25519Signer<C = HttpConnector>
where
    C: Connector,
{
    /// Session with the YubiHSM
    session: Arc<Mutex<YubiHSMSession<C>>>,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: KeyId,
}

impl Ed25519Signer<HttpConnector> {
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

        let pubkey = yubihsm::get_pubkey(&mut session, self.signing_key_id)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if pubkey.algorithm != AsymmetricAlgorithm::EC_ED25519 {
            return Err(ErrorKind::KeyInvalid.into());
        }

        Ok(PublicKey::from_bytes(pubkey.as_ref()).unwrap())
    }

    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let mut session = self.session.lock().unwrap();

        let signature = yubihsm::sign_ed25519(&mut session, self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(Signature::from_bytes(signature.as_ref()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    #[cfg(feature = "yubihsm-mockhsm")]
    use yubihsm::mockhsm::MockHSM;
    #[cfg(feature = "yubihsm-mockhsm")]
    use yubihsm::AuthKey;
    #[cfg(not(feature = "yubihsm-mockhsm"))]
    use yubihsm::Session;
    use yubihsm::{self, AsymmetricAlgorithm, Capability, Domain, ObjectType};

    use super::{Ed25519Signer, KeyId, Signer};

    /// Default authentication key identifier
    const DEFAULT_AUTH_KEY_ID: KeyId = 1;

    /// Key ID to use for test key
    const TEST_SIGNING_KEY_ID: KeyId = 123;

    /// Domain IDs for test key
    const TEST_SIGNING_KEY_DOMAINS: Domain = Domain::DOM1;

    /// Capability for test key
    const TEST_SIGNING_KEY_CAPABILITIES: Capability = Capability::ASYMMETRIC_SIGN_EDDSA;

    /// Label for test key
    const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

    /// Example message to sign
    const TEST_MESSAGE: &[u8] =
        b"The Edwards-curve Digital Signature AsymmetricAlgorithm  (EdDSA) is a \
        variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

    // We need dalek to actually verify the signature
    #[cfg(feature = "dalek-provider")]
    #[test]
    fn generates_signature_verifiable_by_dalek() {
        #[cfg(not(feature = "yubihsm-mockhsm"))]
        let session = Arc::new(Mutex::new(
            Session::create(
                Default::default(),
                DEFAULT_AUTH_KEY_ID,
                AuthKey::default(),
                true,
            ).unwrap_or_else(|err| panic!("error creating session: {}", err)),
        ));

        #[cfg(feature = "yubihsm-mockhsm")]
        let session = Arc::new(Mutex::new(
            MockHSM::new()
                .create_session(DEFAULT_AUTH_KEY_ID, AuthKey::default())
                .unwrap_or_else(|err| panic!("error creating session: {:?}", err)),
        ));

        {
            let mut s = session.lock().unwrap();

            // Delete the key in TEST_KEY_ID slot it exists
            // Ignore errors since the object may not exist yet
            let _ = yubihsm::delete_object(&mut s, TEST_SIGNING_KEY_ID, ObjectType::AsymmetricKey);

            // Create a new key for testing
            yubihsm::generate_asymmetric_key(
                &mut s,
                TEST_SIGNING_KEY_ID,
                TEST_SIGNING_KEY_LABEL.into(),
                TEST_SIGNING_KEY_DOMAINS,
                TEST_SIGNING_KEY_CAPABILITIES,
                AsymmetricAlgorithm::EC_ED25519,
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
