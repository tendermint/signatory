use error::{Error, ErrorKind};
use super::{PublicKey, Signature, Signer};

use yubihsm::{Algorithm, Session};
pub use yubihsm::ObjectId as KeyId;

/// Ed25519 signature provider for yubihsm-client
#[allow(dead_code)]
pub struct YubiHSMSigner<'a> {
    session: Session<'a>,
    signing_key_id: KeyId,
    public_key: PublicKey,
}

impl<'a> YubiHSMSigner<'a> {
    /// Create a new YubiHSMSigner from a yubihsm-client session
    pub fn new(mut session: Session<'a>, signing_key_id: KeyId) -> Result<Self, Error> {
        let pubkey_response = session
            .get_pubkey(signing_key_id)
            .map_err(|e| e.context(ErrorKind::ProviderError))?;

        if pubkey_response.algorithm != Algorithm::EC_ED25519 {
            return Err(ErrorKind::InvalidKey.into());
        }

        Ok(Self {
            session,
            signing_key_id,
            public_key: PublicKey::new(pubkey_response.data.as_ref()),
        })
    }
}

impl<'a> Signer for YubiHSMSigner<'a> {
    fn sign(&mut self, msg: &[u8]) -> Result<Signature, Error> {
        let response = self.session
            .sign_data_eddsa(self.signing_key_id, msg)
            .map_err(|e| e.context(ErrorKind::ProviderError))?;

        Ok(Signature::new(response.signature.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyId, Signer, YubiHSMSigner};
    use ed25519_dalek;
    use sha2::Sha512;
    use yubihsm::{Algorithm, Capabilities, Connector, Domains, ObjectType};

    #[cfg(feature = "yubihsm-mockhsm")]
    use yubihsm::mockhsm::MockHSM;
    #[cfg(feature = "yubihsm-mockhsm")]
    use std::thread;

    /// Connector address when doing live YubiHSM2 tests
    #[cfg(not(feature = "yubihsm-mockhsm"))]
    const CONNECTOR_ADDR: &str = "127.0.0.1:12345";

    /// Connector address for MockHSM tests
    #[cfg(feature = "yubihsm-mockhsm")]
    const CONNECTOR_ADDR: &str = "127.0.0.1:54321";

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

    /// Number of HTTP requests performed by the MockHSM
    #[cfg(feature = "yubihsm-mockhsm")]
    const NUM_MOCKHSM_REQUESTS: usize = 7;

    #[cfg(feature = "yubihsm-mockhsm")]
    fn start_mockhsm() -> thread::JoinHandle<()> {
        thread::spawn(move || {
            MockHSM::new(CONNECTOR_ADDR)
                .unwrap()
                .run(NUM_MOCKHSM_REQUESTS)
        })
    }

    // We need dalek to actually verify the signature
    #[cfg(feature = "dalek-provider")]
    #[test]
    fn generates_signature_verifiable_by_dalek() {
        #[cfg(feature = "yubihsm-mockhsm")]
        let mockhsm_thread = start_mockhsm();

        let connector = Connector::open(&format!("http://{}", CONNECTOR_ADDR))
            .unwrap_or_else(|err| panic!("cannot open connection to yubihsm-connector: {:?}", err));

        let mut session = connector
            .create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
            .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

        // Delete the key in TEST_KEY_ID slot it exists
        // Ignore errors since the object may not exist yet
        let _ = session.delete_object(TEST_SIGNING_KEY_ID, ObjectType::Asymmetric);

        // Create a new key for testing
        session
            .generate_asymmetric_key(
                TEST_SIGNING_KEY_ID,
                TEST_SIGNING_KEY_LABEL.into(),
                TEST_SIGNING_KEY_DOMAINS,
                TEST_SIGNING_KEY_CAPABILITIES,
                Algorithm::EC_ED25519,
            )
            .unwrap();

        let mut signer = YubiHSMSigner::new(session, TEST_SIGNING_KEY_ID).unwrap();
        let signature = signer.sign(TEST_MESSAGE).unwrap();

        let public_key =
            ed25519_dalek::PublicKey::from_bytes(signer.public_key.as_bytes()).unwrap();

        assert!(
            public_key.verify::<Sha512>(
                TEST_MESSAGE,
                &ed25519_dalek::Signature::from_bytes(signature.as_bytes()).unwrap()
            ),
            "Ed25519 signature verification failed!"
        );

        #[cfg(feature = "yubihsm-mockhsm")]
        mockhsm_thread.join().unwrap();
    }
}
