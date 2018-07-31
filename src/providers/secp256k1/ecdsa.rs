//! ECDSA provider for the `secp256k1` crate

use generic_array::{typenum::U32, GenericArray};
use secp256k1::{
    key::PublicKey as Secp256k1PublicKey, key::SecretKey, Message, Secp256k1 as Secp256k1Engine,
    Signature as Secp256k1Signature,
};
use sha2::{Digest, Sha256};

use ecdsa::{
    curve::secp256k1::{DERSignature, FixedSignature, PublicKey, Secp256k1},
    signer::*,
    verifier::*,
};
use error::Error;

lazy_static! {
    /// Lazily initialized secp256k1 engine
    static ref SECP256K1_ENGINE: Secp256k1Engine = Secp256k1Engine::new();
}

/// ECDSA signature provider for the secp256k1 crate
pub struct ECDSASigner(SecretKey);

impl ECDSASigner {
    /// Create a new secp256k1 signer from the given private key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match SecretKey::from_slice(&SECP256K1_ENGINE, bytes) {
            Ok(sk) => Ok(ECDSASigner(sk)),
            Err(e) => fail!(KeyInvalid, "{}", e),
        }
    }
}

impl Signer<Secp256k1> for ECDSASigner {
    /// Return the public key that corresponds to the private key for this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        match Secp256k1PublicKey::from_secret_key(&SECP256K1_ENGINE, &self.0) {
            Ok(pk) => PublicKey::from_slice(&pk.serialize()[..]),
            Err(e) => fail!(KeyInvalid, "{}", e),
        }
    }
}

impl RawDigestDERSigner<Secp256k1> for ECDSASigner {
    /// Compute an ASN.1 DER-encoded signature of the given 32-byte SHA-256 digest
    fn sign_digest_der(&self, msg: &GenericArray<u8, U32>) -> Result<DERSignature, Error> {
        let m = Message::from_slice(msg.as_slice()).unwrap();
        match SECP256K1_ENGINE.sign(&m, &self.0) {
            Ok(sig) => Ok(DERSignature::from_bytes(sig.serialize_der(&SECP256K1_ENGINE)).unwrap()),
            Err(e) => fail!(ProviderError, "{}", e),
        }
    }
}

impl RawDigestFixedSigner<Secp256k1> for ECDSASigner {
    /// Compute a compact, fixed-sized signature of the given 32-byte SHA-256 digest
    fn sign_digest_fixed(&self, msg: &GenericArray<u8, U32>) -> Result<FixedSignature, Error> {
        let m = Message::from_slice(msg.as_slice()).unwrap();
        match SECP256K1_ENGINE.sign(&m, &self.0) {
            Ok(sig) => Ok(FixedSignature::from_bytes(
                &sig.serialize_compact(&SECP256K1_ENGINE)[..],
            ).unwrap()),
            Err(e) => fail!(ProviderError, "{}", e),
        }
    }
}

impl SHA256DERSigner<Secp256k1> for ECDSASigner {
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature, Error> {
        self.sign_digest_der(&Sha256::digest(msg))
    }
}

impl SHA256FixedSigner<Secp256k1> for ECDSASigner {
    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature, Error> {
        self.sign_digest_fixed(&Sha256::digest(msg))
    }
}

/// ECDSA verifier provider for the secp256k1 crate
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ECDSAVerifier;

impl RawDigestDERVerifier<Secp256k1> for ECDSAVerifier {
    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    fn verify_digest_der_signature(
        key: &PublicKey,
        msg: &GenericArray<u8, U32>,
        signature: &DERSignature,
    ) -> Result<(), Error> {
        let sig = Secp256k1Signature::from_der(&SECP256K1_ENGINE, signature.as_bytes())
            .map_err(|e| err!(SignatureInvalid, "{}", e))?;

        verify_signature(key, msg.as_slice(), &sig)
    }
}

impl RawDigestFixedVerifier<Secp256k1> for ECDSAVerifier {
    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_digest_fixed_signature(
        key: &PublicKey,
        msg: &GenericArray<u8, U32>,
        signature: &FixedSignature,
    ) -> Result<(), Error> {
        let sig =
            Secp256k1Signature::from_compact(&SECP256K1_ENGINE, signature.as_bytes()).unwrap();
        verify_signature(key, msg.as_slice(), &sig)
    }
}

/// Verify a secp256k1 signature, abstract across the signature type
///
/// Panics is the message is not 32-bytes
fn verify_signature(
    key: &PublicKey,
    msg: &[u8],
    signature: &Secp256k1Signature,
) -> Result<(), Error> {
    let pk = Secp256k1PublicKey::from_slice(&SECP256K1_ENGINE, key.as_bytes()).unwrap();

    SECP256K1_ENGINE
        .verify(&Message::from_slice(msg).unwrap(), signature, &pk)
        .map_err(|e| err!(SignatureInvalid, "{}", e))
}

// TODO: test against actual test vectors, rather than just checking if signatures roundtrip
#[cfg(test)]
mod tests {
    use super::{ECDSASigner, ECDSAVerifier, Signer};
    use ecdsa::{
        curve::secp256k1::{
            DERSignature, FixedSignature, PublicKey, SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        signer::*,
        verifier::*,
    };

    #[test]
    pub fn der_signature_roundtrip() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha256_der(vector.msg).unwrap();

        let public_key = signer.public_key().unwrap();
        ECDSAVerifier::verify_sha256_der_signature(&public_key, vector.msg, &signature).unwrap();
    }

    #[test]
    pub fn rejects_tweaked_der_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha256_der(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = ECDSAVerifier::verify_sha256_der_signature(
            &public_key,
            vector.msg,
            &DERSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }

    #[test]
    pub fn fixed_signature_vectors() {
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
            let public_key = PublicKey::from_slice(vector.pk).unwrap();
            assert_eq!(signer.public_key().unwrap(), public_key);

            let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
            assert_eq!(signature.as_ref(), vector.sig);

            ECDSAVerifier::verify_sha256_fixed_signature(&public_key, vector.msg, &signature)
                .unwrap();
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = ECDSAVerifier::verify_sha256_fixed_signature(
            &public_key,
            vector.msg,
            &FixedSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }
}
