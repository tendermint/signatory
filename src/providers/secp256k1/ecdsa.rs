/// ECDSA signer implementation for the secp256k1 crate

use generic_array::GenericArray;
use generic_array::typenum::U32;
use secp256k1::Message;
use secp256k1::Secp256k1 as SecpEngine;
use secp256k1::key::PublicKey as SecpPublicKey;
use secp256k1::Signature as SecpSignature;
use secp256k1::key::SecretKey;
use sha2::{Digest, Sha256};

pub use ecdsa::{FixedSizeInputSigner, FixedSizeInputVerifier, Signer, Verifier};
pub use ecdsa::curve::secp256k1::{DERSignature, PublicKey, RawSignature};
use ecdsa::curve::Secp256k1;
use error::Error;

lazy_static! {
    /// Lazily initialized secp256k1 engine
    static ref SECP256K1_ENGINE: SecpEngine = SecpEngine::new();
}

/// ECDSA signature provider for the secp256k1 crate
pub struct ECDSASigner {
    /// Secp256k1 secret key
    secret_key: SecretKey,
}

impl ECDSASigner {
    /// Create a new secp256k1 signer from the given private key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let secret_key =
            SecretKey::from_slice(&SECP256K1_ENGINE, bytes).map_err(|e| err!(KeyInvalid, "{}", e))?;

        Ok(Self { secret_key })
    }
}

impl Signer<Secp256k1> for ECDSASigner {
    /// Return the public key that corresponds to the private key for this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let public_key = SecpPublicKey::from_secret_key(&SECP256K1_ENGINE, &self.secret_key)
            .map_err(|e| err!(KeyInvalid, "{}", e))?;

        PublicKey::from_bytes(&public_key.serialize()[..])
    }

    /// Compute a compact, fixed-sized signature of the SHA-256 digest of the
    /// given input message
    fn sign_sha2_raw(&self, msg: &[u8]) -> Result<RawSignature, Error> {
        self.sign_fixed_raw(&Sha256::digest(msg))
    }

    /// Compute an ASN.1 DER-encoded signature of the SHA-256 digest of the
    /// given input message
    fn sign_sha2_der(&self, msg: &[u8]) -> Result<DERSignature, Error> {
        self.sign_fixed_der(&Sha256::digest(msg))
    }
}

impl FixedSizeInputSigner<Secp256k1> for ECDSASigner {
    /// Compute a compact, fixed-sized signature of the given 32-byte message
    fn sign_fixed_raw(&self, msg: &GenericArray<u8, U32>) -> Result<RawSignature, Error> {
        let signature = SECP256K1_ENGINE
            .sign(
                &Message::from_slice(msg.as_slice()).unwrap(),
                &self.secret_key,
            )
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(RawSignature::from_bytes(&signature.serialize_compact(&SECP256K1_ENGINE)[..]).unwrap())
    }

    /// Compute an ASN.1 DER-encoded signature of the given 32-byte message
    fn sign_fixed_der(&self, msg: &GenericArray<u8, U32>) -> Result<DERSignature, Error> {
        let signature = SECP256K1_ENGINE
            .sign(
                &Message::from_slice(msg.as_slice()).unwrap(),
                &self.secret_key,
            )
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(DERSignature::from_bytes(signature.serialize_der(&SECP256K1_ENGINE)).unwrap())
    }
}

/// ECDSA verifier provider for the secp256k1 crate
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ECDSAVerifier {}

impl Verifier<Secp256k1> for ECDSAVerifier {
    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_sha2_raw_signature(
        key: &PublicKey,
        msg: &[u8],
        signature: &RawSignature,
    ) -> Result<(), Error> {
        Self::verify_fixed_raw_signature(key, &Sha256::digest(msg), signature)
    }

    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    fn verify_sha2_der_signature(
        key: &PublicKey,
        msg: &[u8],
        signature: &DERSignature,
    ) -> Result<(), Error> {
        Self::verify_fixed_der_signature(key, &Sha256::digest(msg), signature)
    }
}

impl FixedSizeInputVerifier<Secp256k1> for ECDSAVerifier {
    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_fixed_raw_signature(
        key: &PublicKey,
        msg: &GenericArray<u8, U32>,
        signature: &RawSignature,
    ) -> Result<(), Error> {
        let sig = SecpSignature::from_compact(&SECP256K1_ENGINE, signature.as_bytes()).unwrap();
        verify_signature(key, msg.as_slice(), &sig)
    }

    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    fn verify_fixed_der_signature(
        key: &PublicKey,
        msg: &GenericArray<u8, U32>,
        signature: &DERSignature,
    ) -> Result<(), Error> {
        let sig = SecpSignature::from_der(&SECP256K1_ENGINE, signature.as_bytes())
            .map_err(|e| err!(SignatureInvalid, "{}", e))?;

        verify_signature(key, msg.as_slice(), &sig)
    }
}

/// Verify a secp256k1 signature, abstract across the signature type
///
/// Panics is the message is not 32-bytes
fn verify_signature(key: &PublicKey, msg: &[u8], signature: &SecpSignature) -> Result<(), Error> {
    let pk = SecpPublicKey::from_slice(&SECP256K1_ENGINE, key.as_bytes()).unwrap();

    SECP256K1_ENGINE
        .verify(&Message::from_slice(msg).unwrap(), signature, &pk)
        .map_err(|e| err!(SignatureInvalid, "{}", e))
}

// TODO: test against actual test vectors, rather than just checking if signatures roundtrip
#[cfg(test)]
mod tests {
    use super::{ECDSASigner, ECDSAVerifier, Signer, Verifier};
    use ecdsa::curve::secp256k1::{DERSignature, RawSignature};
    // TODO: Actually test against real vectors! These vectors are bogus!
    use ecdsa::curve::secp256k1::RAW_TEST_VECTORS;

    #[test]
    pub fn raw_signature_roundtrip() {
        let vector = &RAW_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha2_raw(vector.msg).unwrap();

        let public_key = signer.public_key().unwrap();
        ECDSAVerifier::verify_sha2_raw_signature(&public_key, vector.msg, &signature).unwrap();
    }

    #[test]
    pub fn rejects_tweaked_raw_signature() {
        let vector = &RAW_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha2_raw(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        tweaked_signature[0] ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = ECDSAVerifier::verify_sha2_raw_signature(
            &public_key,
            vector.msg,
            &RawSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }

    #[test]
    pub fn asn1_der_signature_roundtrip() {
        let vector = &RAW_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha2_der(vector.msg).unwrap();

        let public_key = signer.public_key().unwrap();
        ECDSAVerifier::verify_sha2_der_signature(&public_key, vector.msg, &signature).unwrap();
    }

    #[test]
    pub fn rejects_tweaked_asn1_der_signature() {
        let vector = &RAW_TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let signature = signer.sign_sha2_der(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        tweaked_signature[0] ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = ECDSAVerifier::verify_sha2_der_signature(
            &public_key,
            vector.msg,
            &DERSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }
}
