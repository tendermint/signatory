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
pub struct Ed25519Signer<A>
where
    A: yubihsm::Adapter,
{
    /// Session with the YubiHSM
    session: Arc<Mutex<yubihsm::Session<A>>>,

    /// ID of an Ed25519 key to perform signatures with
    signing_key_id: KeyId,
}

impl<A> Ed25519Signer<A>
where
    A: yubihsm::Adapter,
{
    /// Create a new YubiHSM-backed Ed25519 signer
    pub(crate) fn new(session: &Session<A>, signing_key_id: KeyId) -> Result<Self, Error> {
        let signer = Self {
            session: session.0.clone(),
            signing_key_id,
        };

        // Ensure the signing_key_id slot contains a valid Ed25519 public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl<A> PublicKeyed<Ed25519PublicKey> for Ed25519Signer<A>
where
    A: yubihsm::Adapter,
{
    fn public_key(&self) -> Result<Ed25519PublicKey, Error> {
        let mut session = self.session.lock().unwrap();

        let pubkey = yubihsm::get_pubkey(&mut session, self.signing_key_id)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if pubkey.algorithm != yubihsm::AsymmetricAlg::Ed25519 {
            return Err(ErrorKind::KeyInvalid.into());
        }

        Ok(Ed25519PublicKey::from_bytes(pubkey.as_ref()).unwrap())
    }
}

impl<'a, A> Signer<&'a [u8], Ed25519Signature> for Ed25519Signer<A>
where
    A: yubihsm::Adapter,
{
    fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, Error> {
        let mut session = self.session.lock().unwrap();

        let signature = yubihsm::sign_ed25519(&mut session, self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(Ed25519Signature::from_bytes(signature.as_ref()).unwrap())
    }
}

#[cfg(test)]
mod tests {
    extern crate signatory_ring;
    use self::signatory_ring::ed25519::Ed25519Verifier;

    use signatory::{self, PublicKeyed};
    use std::sync::{Arc, Mutex};
    use yubihsm;

    use super::{Ed25519Signer, KeyId, Signer};

    /// Key ID to use for test key
    const TEST_SIGNING_KEY_ID: KeyId = 200;

    /// Domain IDs for test key
    const TEST_SIGNING_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

    /// Capability for test key
    const TEST_SIGNING_KEY_CAPABILITIES: yubihsm::Capability =
        yubihsm::Capability::ASYMMETRIC_SIGN_EDDSA;

    /// Label for test key
    const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

    /// Example message to sign
    const TEST_MESSAGE: &[u8] =
        b"The Edwards-curve Digital Signature yubihsm::AsymmetricAlg  (EdDSA) is a \
        variant of Schnorr's signature system with (possibly twisted) Edwards curves.";

    #[cfg(not(any(feature = "usb", feature = "mockhsm")))]
    type AdapterType = yubihsm::HttpAdapter;

    #[cfg(all(feature = "usb", not(feature = "mockhsm")))]
    type AdapterType = yubihsm::UsbAdapter;

    #[cfg(feature = "mockhsm")]
    type AdapterType = yubihsm::MockAdapter;

    #[test]
    fn ed25519_sign_test() {
        let session = Arc::new(Mutex::new(
            yubihsm::Session::<AdapterType>::create(Default::default(), Default::default(), true)
                .unwrap_or_else(|err| panic!("error creating session: {}", err)),
        ));

        {
            let mut s = session.lock().unwrap();

            // Delete the key in TEST_KEY_ID slot it exists
            // Ignore errors since the object may not exist yet
            let _ = yubihsm::delete_object(
                &mut s,
                TEST_SIGNING_KEY_ID,
                yubihsm::ObjectType::AsymmetricKey,
            );

            // Create a new key for testing
            yubihsm::generate_asymmetric_key(
                &mut s,
                TEST_SIGNING_KEY_ID,
                TEST_SIGNING_KEY_LABEL.into(),
                TEST_SIGNING_KEY_DOMAINS,
                TEST_SIGNING_KEY_CAPABILITIES,
                yubihsm::AsymmetricAlg::Ed25519,
            ).unwrap();
        }

        let signer = Ed25519Signer {
            session,
            signing_key_id: TEST_SIGNING_KEY_ID,
        };

        let signature = signer.sign(TEST_MESSAGE).unwrap();
        let verifier = Ed25519Verifier::from(&signer.public_key().unwrap());

        assert!(signatory::verify(&verifier, TEST_MESSAGE, &signature).is_ok());
    }
}
