//! ECDSA provider for the *ring* crate (supporting NIST P-256)

use ring::{
    self,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair,
        Signature, SigningAlgorithm,
    },
};
use signatory::{
    curve::{nistp256::NISTP256, WeierstrassCurve},
    ecdsa::{signer::*, verifier::*, DERSignature, FixedSignature, PublicKey},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    pkcs8::FromPKCS8,
};

use untrusted::Input;

/// Generic ECDSA signer for use with *ring*
struct ECDSASigner<C: WeierstrassCurve> {
    /// *ring* ECDSA keypair
    keypair: KeyPair,

    /// Public key for this keypair
    // *ring* does not presently keep a copy of this.
    // See https://github.com/briansmith/ring/issues/672#issuecomment-404669397
    public_key: PublicKey<C>,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,
}

impl<C> ECDSASigner<C>
where
    C: WeierstrassCurve,
{
    /// Create a new ECDSA signer from a PKCS#8 keypair
    fn from_pkcs8(alg: &'static SigningAlgorithm, pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let keypair = ring::signature::key_pair_from_pkcs8(alg, Input::from(pkcs8_bytes))
            .map_err(|_| err!(KeyInvalid, "invalid PKCS#8 key"))?;

        let pk_bytes_pos = pkcs8_bytes
            .len()
            .checked_sub(C::UntaggedPointSize::to_usize())
            .unwrap();

        let public_key =
            PublicKey::from_untagged_point(&GenericArray::from_slice(&pkcs8_bytes[pk_bytes_pos..]));

        let csrng = SystemRandom::new();

        Ok(Self {
            keypair,
            public_key,
            csrng,
        })
    }

    /// Sign a message, returning a *ring* Signature type
    fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        ring::signature::sign(&self.keypair, &self.csrng, Input::from(msg))
            .map_err(|_| err!(ProviderError, "signing failure"))
    }
}

/// NIST P-256 ECDSA signer which produces ASN.1 DER encoded signatures
pub struct P256Signer(ECDSASigner<NISTP256>);

impl FromPKCS8 for P256Signer {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let signer = ECDSASigner::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)?;
        Ok(P256Signer(signer))
    }
}

impl Signer<NISTP256> for P256Signer {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<NISTP256>, Error> {
        Ok(self.0.public_key.clone())
    }
}

impl SHA256Signer<NISTP256> for P256Signer {
    /// Compute a compact, fixed-sized signature of the given message
    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature<NISTP256>, Error> {
        FixedSignature::from_bytes(self.0.sign(msg)?)
    }
}

/// NIST P-256 ECDSA verifier for ASN.1 DER encoded signatures
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct P256Verifier;

impl SHA256Verifier<NISTP256> for P256Verifier {
    /// Verify an ASN.1 DER-encoded ECDSA signature against the given public key
    fn verify_sha256_der_signature(
        pubkey: &PublicKey<NISTP256>,
        msg: &[u8],
        signature: &DERSignature<NISTP256>,
    ) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_ASN1,
            Input::from(pubkey.as_ref()),
            Input::from(msg),
            Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }

    /// Verify a fixed-sized (a.k.a. "compact") ECDSA signature against the given public key
    fn verify_sha256_fixed_signature(
        pubkey: &PublicKey<NISTP256>,
        msg: &[u8],
        signature: &FixedSignature<NISTP256>,
    ) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_FIXED,
            Input::from(pubkey.as_ref()),
            Input::from(msg),
            Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }
}

#[cfg(test)]
mod tests {
    use signatory::generic_array::GenericArray;

    use super::{P256Signer, P256Verifier};
    use signatory::{
        curve::nistp256::{
            DERSignature, FixedSignature, PublicKey, SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        ecdsa::{signer::*, verifier::*},
        pkcs8::FromPKCS8,
    };

    #[test]
    pub fn der_signature_roundtrip() {
        // TODO: DER test vectors
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature = signer.sign_sha256_der(vector.msg).unwrap();

        let public_key = signer.public_key().unwrap();
        P256Verifier::verify_sha256_der_signature(&public_key, vector.msg, &signature).unwrap();
    }

    #[test]
    pub fn rejects_tweaked_der_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature = signer.sign_sha256_der(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = P256Verifier::verify_sha256_der_signature(
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
            let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();

            // Make sure we compute the vector's public key
            let public_key = PublicKey::from_untagged_point(&GenericArray::from_slice(vector.pk));

            assert_eq!(signer.public_key().unwrap(), public_key);

            // Compute a signature with a random `k`
            // TODO: test deterministic `k`
            let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
            P256Verifier::verify_sha256_fixed_signature(&public_key, vector.msg, &signature)
                .unwrap();

            // Make sure the vector signature verifies
            P256Verifier::verify_sha256_fixed_signature(
                &public_key,
                vector.msg,
                &FixedSignature::from_bytes(&vector.sig).unwrap(),
            ).unwrap();
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = P256Verifier::verify_sha256_fixed_signature(
            &public_key,
            vector.msg,
            &FixedSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }

    #[test]
    fn test_fixed_to_asn1_transformed_signature_verifies() {
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
            let public_key = signer.public_key().unwrap();

            let der_signature = DERSignature::from(&signer.sign_sha256_fixed(vector.msg).unwrap());
            P256Verifier::verify_sha256_der_signature(&public_key, vector.msg, &der_signature)
                .unwrap();
        }
    }
}
