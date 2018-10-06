// TODO: upstream MockHSM support for ECDSA
#![cfg_attr(feature = "mockhsm", allow(unused_imports, dead_code))]

extern crate signatory;
extern crate signatory_ring;
#[cfg(all(feature = "secp256k1", not(feature = "mockhsm")))]
extern crate signatory_secp256k1;
extern crate signatory_yubihsm;
extern crate yubihsm;
#[macro_use]
extern crate lazy_static;

pub mod support;

#[cfg(all(feature = "secp256k1", not(feature = "mockhsm")))]
use signatory::curve::Secp256k1;
use signatory::{
    curve::{NistP256, NistP384, WeierstrassCurve},
    ecdsa::Asn1Signature,
    PublicKeyed,
};
use signatory_ring::ecdsa;
#[cfg(all(feature = "secp256k1", not(feature = "mockhsm")))]
use signatory_secp256k1::EcdsaVerifier as Secp256k1Verifier;

use signatory_yubihsm::{EcdsaSigner, KeyId, Session};

/// Domain IDs for test key
const TEST_SIGNING_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

/// Capability for test key
const TEST_SIGNING_KEY_CAPABILITIES: yubihsm::Capability =
    yubihsm::Capability::ASYMMETRIC_SIGN_ECDSA;

/// Label for test key
const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

/// Example message to sign
const TEST_MESSAGE: &[u8] =
    b"The Elliptic Curve Digital Signature Algorithm (ECDSA) is a variant of the \
      Digital Signature Algorithm (DSA) which uses elliptic curve cryptography.";

/// Create the signer for this test
fn create_signer<C>(key_id: KeyId) -> EcdsaSigner<C>
where
    C: WeierstrassCurve,
{
    let mut session = support::get_session();
    create_yubihsm_key(&mut session, key_id, EcdsaSigner::<C>::asymmetric_alg());

    session.ecdsa_signer(key_id).unwrap()
}

/// Create the key on the YubiHSM to use for this test
fn create_yubihsm_key(session: &mut Session, key_id: KeyId, alg: yubihsm::AsymmetricAlg) {
    let client_guard = session.client();
    let mut hsm = client_guard.lock().unwrap();

    // Delete the key in TEST_KEY_ID slot it exists
    // Ignore errors since the object may not exist yet
    let _ = hsm.delete_object(key_id.0, yubihsm::ObjectType::AsymmetricKey);

    // Create a new key for testing
    hsm.generate_asymmetric_key(
        key_id.0,
        TEST_SIGNING_KEY_LABEL.into(),
        TEST_SIGNING_KEY_DOMAINS,
        TEST_SIGNING_KEY_CAPABILITIES,
        alg,
    ).unwrap();
}

// Use *ring* to verify NIST P-256 ECDSA signatures
#[test]
#[cfg(not(feature = "mockhsm"))]
fn ecdsa_nistp256_sign_test() {
    let signer = create_signer::<NistP256>(KeyId(100));
    let signature: Asn1Signature<_> = signatory::sign_sha256(&signer, TEST_MESSAGE).unwrap();

    let verifier = ecdsa::P256Verifier::from(&signer.public_key().unwrap());
    assert!(signatory::verify_sha256(&verifier, TEST_MESSAGE, &signature).is_ok());
}

// Use *ring* to verify NIST P-384 ECDSA signatures
#[cfg(not(feature = "mockhsm"))]
#[test]
fn ecdsa_nistp384_sign_test() {
    let signer = create_signer::<NistP384>(KeyId(101));
    let signature: Asn1Signature<_> = signatory::sign_sha384(&signer, TEST_MESSAGE).unwrap();

    let verifier = ecdsa::P384Verifier::from(&signer.public_key().unwrap());
    assert!(signatory::verify_sha384(&verifier, TEST_MESSAGE, &signature).is_ok());
}

// Use `secp256k1` crate to verify secp256k1 ECDSA signatures.
// The MockHSM does not presently support secp256k1
#[cfg(all(feature = "secp256k1", not(feature = "mockhsm")))]
#[test]
fn ecdsa_secp256k1_sign_test() {
    let signer = create_signer::<Secp256k1>(KeyId(102));
    let signature: Asn1Signature<_> = signatory::sign_sha256(&signer, TEST_MESSAGE).unwrap();

    let verifier = Secp256k1Verifier::from(&signer.public_key().unwrap());

    assert!(signatory::verify_sha256(&verifier, TEST_MESSAGE, &signature).is_ok());
}
