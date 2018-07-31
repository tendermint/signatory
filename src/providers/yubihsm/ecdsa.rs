//! ECDSA provider for the YubiHSM2 crate (supporting NIST P-256 and secp256k1)

use generic_array::typenum::{U32, Unsigned};
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use yubihsm_crate;

use super::{KeyId, Session};
use ecdsa::{curve::WeierstrassCurve, signer::*, DERSignature, PublicKey};
use error::Error;

/// ECDSA signature provider for yubihsm-client
pub struct ECDSASigner<Curve, Connector = yubihsm_crate::HttpConnector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm_crate::Connector,
{
    /// Session with the YubiHSM
    session: Arc<Mutex<yubihsm_crate::Session<Connector>>>,

    /// ID of an ECDSA key to perform signatures with
    signing_key_id: KeyId,

    /// Placeholder for elliptic curve type
    curve: PhantomData<Curve>,
}

impl<Curve> ECDSASigner<Curve, yubihsm_crate::HttpConnector>
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

impl<Curve, Connector> ECDSASigner<Curve, Connector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm_crate::Connector,
{
    /// Get the expected `yubihsm::AsymmetricAlgorithm` for this `Curve`
    fn asymmetric_algorithm() -> Option<yubihsm_crate::AsymmetricAlgorithm> {
        match Curve::ID {
            "nistp256" => Some(yubihsm_crate::AsymmetricAlgorithm::EC_P256),
            "secp256k1" => Some(yubihsm_crate::AsymmetricAlgorithm::EC_K256),
            _ => None,
        }
    }
}

impl<Curve, Connector> Signer<Curve> for ECDSASigner<Curve, Connector>
where
    Curve: WeierstrassCurve,
    Connector: yubihsm_crate::Connector,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<Curve>, Error> {
        let mut session = self.session.lock().unwrap();

        let pubkey = yubihsm_crate::get_pubkey(&mut session, self.signing_key_id)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if Some(pubkey.algorithm) != Self::asymmetric_algorithm() {
            fail!(
                KeyInvalid,
                "expected a {} key, got: {:?}",
                Curve::ID,
                pubkey.algorithm
            );
        }

        Ok(PublicKey::from_bytes(pubkey.as_ref()).unwrap())
    }
}

// TODO: figure out how to keep the concrete MockConnector type from leaking out
// The MockHSM implementation of ECDSA does some odd workarounds for the *ring*
// API since it's slightly incompatible with the API provided by the MockHSM
// See: https://github.com/briansmith/ring/issues/253
#[cfg(not(feature = "yubihsm-mockhsm"))]
impl<Curve, Connector> SHA256DERSigner<Curve> for ECDSASigner<Curve, Connector>
where
    Curve: WeierstrassCurve<PrivateScalarSize = U32>,
    Connector: yubihsm_crate::Connector,
{
    /// Compute an ASN.1 DER-encoded signature of the given message
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<Curve>, Error> {
        let mut session = self.session.lock().unwrap();

        let signature = yubihsm_crate::sign_ecdsa_sha256(&mut session, self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        let length = signature.as_ref().len();

        if length > Curve::DERSignatureMaxSize::to_usize()
            || length <= Curve::FixedSignatureSize::to_usize()
        {
            fail!(
                ProviderError,
                "unexpected signature size for {}: {}",
                Curve::ID,
                length
            );
        }

        DERSignature::from_bytes(signature)
    }
}

// TODO: figure out how to keep the concrete MockConnector type from leaking out (see above)
#[cfg(feature = "yubihsm-mockhsm")]
impl<Curve> SHA256DERSigner<Curve> for ECDSASigner<Curve, yubihsm_crate::mockhsm::MockConnector>
where
    Curve: WeierstrassCurve<PrivateScalarSize = U32>,
{
    /// Compute an ASN.1 DER-encoded signature of the given message
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<Curve>, Error> {
        let mut session = self.session.lock().unwrap();

        let signature = yubihsm_crate::sign_ecdsa_sha256(&mut session, self.signing_key_id, msg)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        let length = signature.as_ref().len();

        if length > Curve::DERSignatureMaxSize::to_usize()
            || length <= Curve::FixedSignatureSize::to_usize()
        {
            fail!(
                ProviderError,
                "unexpected signature size for {}: {}",
                Curve::ID,
                length
            );
        }

        DERSignature::from_bytes(signature)
    }
}

#[cfg(test)]
mod tests {
    // TODO: fix secp256k1
    #![allow(unused_imports)]

    #[cfg(feature = "ring-provider")]
    use providers::ring;
    #[cfg(feature = "secp256k1-provider")]
    use providers::secp256k1;
    use std::marker::PhantomData;
    use std::sync::{Arc, Mutex};
    use yubihsm_crate;

    use super::{ECDSASigner, KeyId, Signer};
    use ecdsa::{
        curve::{NISTP256, Secp256k1, WeierstrassCurve},
        signer::SHA256DERSigner,
        verifier::SHA256DERVerifier,
    };

    /// Default authentication key identifier
    const DEFAULT_AUTH_KEY_ID: KeyId = 1;

    /// Domain IDs for test key
    const TEST_SIGNING_KEY_DOMAINS: yubihsm_crate::Domain = yubihsm_crate::Domain::DOM1;

    /// Capability for test key
    const TEST_SIGNING_KEY_CAPABILITIES: yubihsm_crate::Capability =
        yubihsm_crate::Capability::ASYMMETRIC_SIGN_ECDSA;

    /// Label for test key
    const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

    /// Example message to sign
    const TEST_MESSAGE: &[u8] =
        b"The Elliptic Curve Digital Signature Algorithm (ECDSA) is a variant of the \
          Digital Signature Algorithm (DSA) which uses elliptic curve cryptography.";

    #[cfg(not(feature = "yubihsm-mockhsm"))]
    type ConnectorType = yubihsm_crate::HttpConnector;

    #[cfg(feature = "yubihsm-mockhsm")]
    type ConnectorType = yubihsm_crate::mockhsm::MockConnector;

    /// Create the signer for this test
    fn create_signer<Curve>(key_id: KeyId) -> ECDSASigner<Curve, ConnectorType>
    where
        Curve: WeierstrassCurve,
    {
        #[cfg(not(feature = "yubihsm-mockhsm"))]
        let session = Arc::new(Mutex::new(
            yubihsm_crate::Session::create(
                Default::default(),
                DEFAULT_AUTH_KEY_ID,
                yubihsm_crate::AuthKey::default(),
                true,
            ).unwrap_or_else(|err| panic!("error creating session: {}", err)),
        ));

        #[cfg(feature = "yubihsm-mockhsm")]
        let session = Arc::new(Mutex::new(
            yubihsm_crate::mockhsm::MockHSM::new()
                .create_session(DEFAULT_AUTH_KEY_ID, yubihsm_crate::AuthKey::default())
                .unwrap_or_else(|err| panic!("error creating session: {:?}", err)),
        ));

        let signer = ECDSASigner {
            session,
            signing_key_id: key_id,
            curve: PhantomData,
        };

        create_yubihsm_key(&signer, key_id);
        signer
    }
    /// Create the key on the YubiHSM to use for this test
    fn create_yubihsm_key<Curve>(signer: &ECDSASigner<Curve, ConnectorType>, key_id: KeyId)
    where
        Curve: WeierstrassCurve,
    {
        let mut s = signer.session.lock().unwrap();

        // Delete the key in TEST_KEY_ID slot it exists
        // Ignore errors since the object may not exist yet
        let _ =
            yubihsm_crate::delete_object(&mut s, key_id, yubihsm_crate::ObjectType::AsymmetricKey);

        // Create a new key for testing
        yubihsm_crate::generate_asymmetric_key(
            &mut s,
            key_id,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            TEST_SIGNING_KEY_CAPABILITIES,
            ECDSASigner::<Curve>::asymmetric_algorithm().unwrap(),
        ).unwrap();
    }

    // We need *ring* to verify NIST P-256 ECDSA signatures
    #[cfg(feature = "ring-provider")]
    #[test]
    fn ecdsa_nistp256_sign_test() {
        let signer = create_signer::<NISTP256>(100);

        let public_key = signer.public_key().unwrap();
        let signature = signer.sign_sha256_der(TEST_MESSAGE).unwrap();

        assert!(
            ring::P256DERVerifier::verify_sha256_der_signature(
                &public_key,
                TEST_MESSAGE,
                &signature
            ).is_ok()
        );
    }

    // We need secp256k1 to verify secp256k1 ECDSA signatures.
    // The MockHSM does not presently support secp256k1
    // TODO: completely refactor our handling of compressed vs uncompressed keys to get this working
    //    #[cfg(
    //        all(
    //            feature = "secp256k1-provider",
    //            not(feature = "yubihsm-mockhsm")
    //        )
    //    )]
    //    #[test]
    //    fn ecdsa_secp256k1_sign_test() {
    //        let signer = create_signer::<Secp256k1>(101);
    //
    //        let public_key = signer.public_key().unwrap();
    //        let signature = signer.sign_sha256_der(TEST_MESSAGE).unwrap();
    //
    //        assert!(
    //            secp256k1::ECDSAVerifier::verify_sha256_der_signature(&public_key, TEST_MESSAGE, &signature)
    //                .is_ok()
    //        );
    //    }
}
