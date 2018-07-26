//! ECDSA provider for the *ring* crate (supporting NIST P-256)

use generic_array::typenum::Unsigned;
use ring::{
    self,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair, Signature, SigningAlgorithm,
    },
};
use untrusted::Input;

use ecdsa::{
    curve::{nistp256::NISTP256, WeierstrassCurve},
    signer::*,
    verifier::*,
    DERSignature, FixedSignature, PublicKey,
};
use error::Error;
// TODO: find a better way to gate this
#[cfg(feature = "std")]
use test_vector::{TestVector, TestVectorAlgorithm};

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

        let public_key = PublicKey::from_bytes(
            &pkcs8_bytes[(pkcs8_bytes.len() - C::DERPublicKeySize::to_usize() + 1)..],
        )?;

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
pub struct P256DERSigner(ECDSASigner<NISTP256>);

impl P256DERSigner {
    /// Create a new ECDSA signer which produces ASN.1 DER signatures from a PKCS#8 keypair
    pub fn from_pkcs8(pkcs_bytes: &[u8]) -> Result<Self, Error> {
        let signer = ECDSASigner::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs_bytes)?;
        Ok(P256DERSigner(signer))
    }

    /// Create a P256FixedSigner from a test vector
    // TODO: replace this with a generic PKCS#8 serializer for test vectors
    #[cfg(all(feature = "std", feature = "test-vectors"))]
    pub fn from_test_vector(vector: &TestVector) -> Self {
        Self::from_pkcs8(&test_vector_to_pkcs8(vector)).unwrap()
    }
}

impl Signer<NISTP256> for P256DERSigner {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<NISTP256>, Error> {
        Ok(self.0.public_key.clone())
    }
}

impl SHA256DERSigner<NISTP256> for P256DERSigner {
    /// Compute an ASN.1 DER-encoded signature of the given 32-byte message
    fn sign_sha256_der(&self, msg: &[u8]) -> Result<DERSignature<NISTP256>, Error> {
        DERSignature::from_bytes(self.0.sign(msg)?)
    }
}

/// NIST P-256 ECDSA signer which produces fixed-sized signatures
pub struct P256FixedSigner(ECDSASigner<NISTP256>);

impl P256FixedSigner {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    pub fn from_pkcs8(pkcs_bytes: &[u8]) -> Result<Self, Error> {
        let signer = ECDSASigner::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs_bytes)?;
        Ok(P256FixedSigner(signer))
    }

    /// Create a P256FixedSigner from a test vector
    // TODO: replace this with a generic PKCS#8 serializer for test vectors
    #[cfg(all(feature = "std", feature = "test-vectors"))]
    pub fn from_test_vector(vector: &TestVector) -> Self {
        Self::from_pkcs8(&test_vector_to_pkcs8(vector)).unwrap()
    }
}

impl Signer<NISTP256> for P256FixedSigner {
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<NISTP256>, Error> {
        Ok(self.0.public_key.clone())
    }
}

impl SHA256FixedSigner<NISTP256> for P256FixedSigner {
    /// Compute a compact, fixed-sized signature of the given 32-byte message
    fn sign_sha256_fixed(&self, msg: &[u8]) -> Result<FixedSignature<NISTP256>, Error> {
        FixedSignature::from_bytes(self.0.sign(msg)?)
    }
}

/// NIST P-256 ECDSA verifier for ASN.1 DER encoded signatures
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct P256DERVerifier;

impl SHA256DERVerifier<NISTP256> for P256DERVerifier {
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
}

/// NIST P-256 ECDSA verifier for fixed-sized signatures
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct P256FixedVerifier;

impl SHA256FixedVerifier<NISTP256> for P256FixedVerifier {
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

/// Serialize this test vector as a PKCS#8 document
// TODO: find a better solution than giant bytestring literals, like a PKCS#8 library
#[cfg(all(feature = "std", feature = "test-vectors"))]
fn test_vector_to_pkcs8(vector: &TestVector) -> ::std::vec::Vec<u8> {
    if vector.alg != TestVectorAlgorithm::NISTP256 {
        panic!("not a NIST P-256 test vector: {:?}", vector.alg);
    }

    // TODO: better PKCS#8 serializer than this
    let mut pkcs8_document = b"\x30\x81\x87\x02\x01\x00\x30\x13\
            \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\
            \x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20"
        .to_vec();

    pkcs8_document.extend_from_slice(&vector.sk);
    pkcs8_document.extend_from_slice(b"\xa1\x44\x03\x42\x00\x04");
    pkcs8_document.extend_from_slice(&vector.pk);

    pkcs8_document
}

#[cfg(test)]
mod tests {
    use super::{P256DERSigner, P256DERVerifier, P256FixedSigner, P256FixedVerifier};
    use ecdsa::{
        curve::nistp256::{
            DERSignature, FixedSignature, PublicKey, SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        signer::*,
        verifier::*,
    };

    #[test]
    pub fn der_signature_roundtrip() {
        // TODO: DER test vectors
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256DERSigner::from_test_vector(vector);
        let signature = signer.sign_sha256_der(vector.msg).unwrap();

        let public_key = signer.public_key().unwrap();
        P256DERVerifier::verify_sha256_der_signature(&public_key, vector.msg, &signature).unwrap();
    }

    #[test]
    pub fn rejects_tweaked_der_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256DERSigner::from_test_vector(&vector);
        let signature = signer.sign_sha256_der(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = P256DERVerifier::verify_sha256_der_signature(
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
            let signer = P256FixedSigner::from_test_vector(vector);

            // Make sure we compute the vector's public key
            let public_key = PublicKey::from_bytes(vector.pk).unwrap();
            assert_eq!(signer.public_key().unwrap(), public_key);

            // Compute a signature with a random `k`
            // TODO: test deterministic `k`
            let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
            P256FixedVerifier::verify_sha256_fixed_signature(&public_key, vector.msg, &signature)
                .unwrap();

            // Make sure the vector signature verifies
            P256FixedVerifier::verify_sha256_fixed_signature(
                &public_key,
                vector.msg,
                &FixedSignature::from_bytes(&vector.sig).unwrap(),
            ).unwrap();
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256FixedSigner::from_test_vector(vector);
        let signature = signer.sign_sha256_fixed(vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let public_key = signer.public_key().unwrap();
        let result = P256FixedVerifier::verify_sha256_fixed_signature(
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
