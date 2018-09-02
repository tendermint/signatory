//! ECDSA provider for the YubiHSM2 crate (supporting NIST P-256 and secp256k1)

#[cfg(not(feature = "mockhsm"))]
use signatory::{curve::CurveDigest, Signer};
#[cfg(feature = "mockhsm")]
use signatory::{curve::NistP256, Sha256Signer};
use signatory::{
    curve::{WeierstrassCurve, WeierstrassCurveKind},
    ecdsa::{Asn1Signature, PublicKey},
    error::Error,
    generic_array::GenericArray,
    PublicKeyed, Signature,
};
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use yubihsm;
#[cfg(feature = "mockhsm")]
use yubihsm::mockhsm::MockConnector;

use super::{KeyId, Session};

/// ECDSA signature provider for yubihsm-client
pub struct EcdsaSigner<Curve, Connector = yubihsm::HttpConnector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm::Connector,
{
    /// Session with the YubiHSM
    session: Arc<Mutex<yubihsm::Session<Connector>>>,

    /// ID of an ECDSA key to perform signatures with
    signing_key_id: KeyId,

    /// Placeholder for elliptic curve type
    curve: PhantomData<Curve>,
}

impl<Curve> EcdsaSigner<Curve, yubihsm::HttpConnector>
where
    Curve: WeierstrassCurve,
{
    /// Create a new YubiHSM-backed ECDSA signer
    pub(crate) fn new(session: &Session, signing_key_id: KeyId) -> Result<Self, Error> {
        let signer = Self {
            session: session.0.clone(),
            signing_key_id,
            curve: PhantomData,
        };

        // Ensure the signing_key_id slot contains a valid ECDSA public key
        signer.public_key()?;

        Ok(signer)
    }
}

impl<Curve, Connector> EcdsaSigner<Curve, Connector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm::Connector,
{
    /// Get the expected `yubihsm::AsymmetricAlgorithm` for this `Curve`
    fn asymmetric_algorithm() -> Option<yubihsm::AsymmetricAlgorithm> {
        match Curve::CURVE_KIND {
            WeierstrassCurveKind::NistP256 => Some(yubihsm::AsymmetricAlgorithm::EC_P256),
            WeierstrassCurveKind::Secp256k1 => Some(yubihsm::AsymmetricAlgorithm::EC_K256),
            _ => None,
        }
    }
}

impl<Curve, Connector> PublicKeyed<PublicKey<Curve>> for EcdsaSigner<Curve, Connector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm::Connector,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<Curve>, Error> {
        let mut session = self.session.lock().unwrap();

        let pubkey = yubihsm::get_pubkey(&mut session, self.signing_key_id)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if Some(pubkey.algorithm) != Self::asymmetric_algorithm() {
            fail!(
                KeyInvalid,
                "expected a {} key, got: {:?}",
                Curve::CURVE_KIND.to_str(),
                pubkey.algorithm
            );
        }

        Ok(PublicKey::from_untagged_point(GenericArray::from_slice(
            pubkey.as_ref(),
        )))
    }
}

// TODO: figure out how to keep the concrete MockConnector type from leaking out
// The MockHSM implementation of ECDSA does some odd workarounds for the *ring*
// API since it's slightly incompatible with the API provided by the MockHSM
// See: https://github.com/briansmith/ring/issues/253
#[cfg(not(feature = "mockhsm"))]
impl<Curve, Connector> Signer<CurveDigest<Curve>, Asn1Signature<Curve>>
    for EcdsaSigner<Curve, Connector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm::Connector,
{
    /// Compute an ASN.1 DER-encoded signature of the given 32-byte SHA-256 digest
    fn sign(&self, digest: CurveDigest<Curve>) -> Result<Asn1Signature<Curve>, Error> {
        let mut session = self.session.lock().unwrap();

        let signature =
            yubihsm::sign_ecdsa_raw_digest(&mut session, self.signing_key_id, digest.as_ref())
                .map_err(|e| err!(ProviderError, "{}", e))?;

        Asn1Signature::from_bytes(signature)
    }
}

// TODO: figure out how to keep the concrete MockConnector type from leaking out (see above)
#[cfg(feature = "mockhsm")]
impl<'a> Sha256Signer<'a, Asn1Signature<NistP256>> for EcdsaSigner<NistP256, MockConnector> {
    /// Compute an ASN.1 DER-encoded signature of the given message
    fn sign_sha256(&self, msg: &'a [u8]) -> Result<Asn1Signature<NistP256>, Error> {
        let mut session = self.session.lock().unwrap();

        let signature = yubihsm::sign_ecdsa_sha256(&mut session, self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Asn1Signature::from_bytes(signature)
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use std::sync::{Arc, Mutex};
    use yubihsm;
    #[cfg(not(feature = "mockhsm"))]
    use yubihsm::HttpConnector;

    use super::*;
    #[cfg(not(feature = "mockhsm"))]
    use signatory::curve::Secp256k1;
    use signatory::{
        self,
        curve::{NistP256, WeierstrassCurve},
        ecdsa::Asn1Signature,
        PublicKeyed, Sha256Verifier,
    };
    use signatory_ring;
    #[cfg(not(feature = "mockhsm"))]
    use signatory_secp256k1;

    /// Default authentication key identifier
    const DEFAULT_AUTH_KEY_ID: KeyId = 1;

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

    #[cfg(not(feature = "mockhsm"))]
    type ConnectorType = HttpConnector;

    #[cfg(feature = "mockhsm")]
    type ConnectorType = MockConnector;

    /// Create the signer for this test
    fn create_signer<Curve>(key_id: KeyId) -> EcdsaSigner<Curve, ConnectorType>
    where
        Curve: WeierstrassCurve,
    {
        #[cfg(not(feature = "mockhsm"))]
        let session = Arc::new(Mutex::new(
            yubihsm::Session::create(
                Default::default(),
                DEFAULT_AUTH_KEY_ID,
                yubihsm::AuthKey::default(),
                true,
            ).unwrap_or_else(|err| panic!("error creating session: {}", err)),
        ));

        #[cfg(feature = "mockhsm")]
        let session = Arc::new(Mutex::new(
            yubihsm::mockhsm::MockHSM::new()
                .create_session(DEFAULT_AUTH_KEY_ID, yubihsm::AuthKey::default())
                .unwrap_or_else(|err| panic!("error creating session: {:?}", err)),
        ));

        let signer = EcdsaSigner {
            session,
            signing_key_id: key_id,
            curve: PhantomData,
        };

        create_yubihsm_key(&signer, key_id);
        signer
    }

    /// Create the key on the YubiHSM to use for this test
    fn create_yubihsm_key<Curve>(signer: &EcdsaSigner<Curve, ConnectorType>, key_id: KeyId)
    where
        Curve: WeierstrassCurve,
    {
        let mut s = signer.session.lock().unwrap();

        // Delete the key in TEST_KEY_ID slot it exists
        // Ignore errors since the object may not exist yet
        let _ = yubihsm::delete_object(&mut s, key_id, yubihsm::ObjectType::AsymmetricKey);

        // Create a new key for testing
        yubihsm::generate_asymmetric_key(
            &mut s,
            key_id,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            TEST_SIGNING_KEY_CAPABILITIES,
            EcdsaSigner::<Curve>::asymmetric_algorithm().unwrap(),
        ).unwrap();
    }

    // We need *ring* to verify NIST P-256 ECDSA signatures
    #[test]
    fn ecdsa_nistp256_sign_test() {
        let signer = create_signer::<NistP256>(100);
        let signature: Asn1Signature<_> = signatory::sign_sha256(&signer, TEST_MESSAGE).unwrap();

        let verifier = signatory_ring::ecdsa::P256Verifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify_sha256(TEST_MESSAGE, &signature).is_ok());
    }

    // We need secp256k1 to verify secp256k1 ECDSA signatures.
    // The MockHSM does not presently support secp256k1
    #[cfg(not(feature = "mockhsm"))]
    #[test]
    fn ecdsa_secp256k1_sign_test() {
        let signer = create_signer::<Secp256k1>(101);
        let signature: Asn1Signature<_> = signatory::sign_sha256(&signer, TEST_MESSAGE).unwrap();

        let verifier = signatory_secp256k1::EcdsaVerifier::from(&signer.public_key().unwrap());

        assert!(verifier.verify_sha256(TEST_MESSAGE, &signature).is_ok());
    }
}
