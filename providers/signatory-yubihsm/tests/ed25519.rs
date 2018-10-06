extern crate signatory;
extern crate signatory_ring;
extern crate signatory_yubihsm;
extern crate yubihsm;
#[macro_use]
extern crate lazy_static;

pub mod support;

use signatory::PublicKeyed;
use signatory_ring::ed25519::Ed25519Verifier;

use signatory_yubihsm::{signatory::Signer, KeyId, Session};

/// Key ID to use for test key
const TEST_SIGNING_KEY_ID: KeyId = KeyId(200);

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

/// Create the key on the YubiHSM to use for this test
fn create_yubihsm_key(session: &mut Session) {
    let client_guard = session.client();
    let mut hsm = client_guard.lock().unwrap();

    // Delete the key in TEST_KEY_ID slot it exists
    // Ignore errors since the object may not exist yet
    let _ = hsm.delete_object(TEST_SIGNING_KEY_ID.0, yubihsm::ObjectType::AsymmetricKey);

    // Create a new key for testing
    hsm.generate_asymmetric_key(
        TEST_SIGNING_KEY_ID.0,
        TEST_SIGNING_KEY_LABEL.into(),
        TEST_SIGNING_KEY_DOMAINS,
        TEST_SIGNING_KEY_CAPABILITIES,
        yubihsm::AsymmetricAlg::Ed25519,
    ).unwrap();
}

#[test]
fn ed25519_sign_test() {
    let mut session = support::get_session();
    create_yubihsm_key(&mut session);

    let signer = session.ed25519_signer(TEST_SIGNING_KEY_ID).unwrap();
    let signature = signer.sign(TEST_MESSAGE).unwrap();
    let verifier = Ed25519Verifier::from(&signer.public_key().unwrap());

    assert!(signatory::verify(&verifier, TEST_MESSAGE, &signature).is_ok());
}
