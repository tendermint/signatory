/// ECDSA signer implementation for secp256k1-rs

use generic_array::GenericArray;
use generic_array::typenum::U32;
use secp256k1::Message;
use secp256k1::Secp256k1 as SecpEngine;
use secp256k1::key::PublicKey as SecpPublicKey;
use secp256k1::key::SecretKey;
use sha2::{Digest, Sha256};

pub use ecdsa::{FixedSizeInputSigner, Signer};
use ecdsa::curve::secp256k1::{DERSignature, PublicKey, RawSignature, Secp256k1};
use error::Error;

/// ECDSA signature provider for secp256k1-rs
pub struct ECDSASigner {
    /// Secp256k1 signature engine
    engine: SecpEngine,

    /// Secp256k1 secret key
    secret_key: SecretKey,
}

impl ECDSASigner {
    /// Create a new secp256k1 signer from the given private key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let engine = SecpEngine::new();
        let secret_key =
            SecretKey::from_slice(&engine, bytes).map_err(|e| err!(KeyInvalid, "{}", e))?;

        Ok(Self { engine, secret_key })
    }
}

impl Signer<Secp256k1> for ECDSASigner {
    /// Return the public key that corresponds to the private key for this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let public_key = SecpPublicKey::from_secret_key(&self.engine, &self.secret_key)
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
        let signature = self.engine
            .sign(
                &Message::from_slice(msg.as_slice()).unwrap(),
                &self.secret_key,
            )
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(RawSignature::from_bytes(&signature.serialize_compact(&self.engine)[..]).unwrap())
    }

    /// Compute an ASN.1 DER-encoded signature of the given 32-byte message
    fn sign_fixed_der(&self, msg: &GenericArray<u8, U32>) -> Result<DERSignature, Error> {
        let signature = self.engine
            .sign(
                &Message::from_slice(msg.as_slice()).unwrap(),
                &self.secret_key,
            )
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Ok(DERSignature::from_bytes(signature.serialize_der(&self.engine)).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::{ECDSASigner, Signer};
    use ecdsa::curve::secp256k1::TEST_VECTORS;

    // TODO: real tests
    #[test]
    pub fn raw_signature() {
        let vector = &TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let _signature = signer.sign_sha2_raw(vector.msg).unwrap();
    }

    #[test]
    pub fn asn1_der_signature() {
        let vector = &TEST_VECTORS[0];

        let signer = ECDSASigner::from_bytes(vector.sk).unwrap();
        let _signature = signer.sign_sha2_der(vector.msg).unwrap();
    }
}
