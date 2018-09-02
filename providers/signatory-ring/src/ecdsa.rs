//! ECDSA provider for the *ring* crate (supporting NIST P-256)

use core::marker::PhantomData;

use ring::{
    self,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING, KeyPair, SigningAlgorithm,
    },
};
use signatory::{
    curve::{nistp256::NistP256, WeierstrassCurve},
    ecdsa::{Asn1Signature, EcdsaSignature, FixedSignature, PublicKey},
    encoding::FromPkcs8,
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    PublicKeyed, Sha256Signer, Sha256Verifier, Signature,
};
use untrusted;

/// NIST P-256 ECDSA signer
pub struct P256Signer<S: EcdsaSignature>(EcdsaSigner<NistP256, S>);

impl FromPkcs8 for P256Signer<Asn1Signature<NistP256>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let signer = EcdsaSigner::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes)?;
        Ok(P256Signer(signer))
    }
}

impl FromPkcs8 for P256Signer<FixedSignature<NistP256>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let signer = EcdsaSigner::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8_bytes)?;
        Ok(P256Signer(signer))
    }
}

impl<S> PublicKeyed<PublicKey<NistP256>> for P256Signer<S>
where
    S: EcdsaSignature + Send + Sync,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<NistP256>, Error> {
        Ok(self.0.public_key.clone())
    }
}

impl<'a> Sha256Signer<'a, Asn1Signature<NistP256>> for P256Signer<Asn1Signature<NistP256>> {
    fn sign_sha256(&self, msg: &'a [u8]) -> Result<Asn1Signature<NistP256>, Error> {
        Asn1Signature::from_bytes(self.0.sign(msg)?)
    }
}

impl<'a> Sha256Signer<'a, FixedSignature<NistP256>> for P256Signer<FixedSignature<NistP256>> {
    fn sign_sha256(&self, msg: &'a [u8]) -> Result<FixedSignature<NistP256>, Error> {
        FixedSignature::from_bytes(self.0.sign(msg)?)
    }
}

/// NIST P-256 ECDSA verifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P256Verifier(PublicKey<NistP256>);

impl<'a> From<&'a PublicKey<NistP256>> for P256Verifier {
    fn from(public_key: &'a PublicKey<NistP256>) -> Self {
        P256Verifier(public_key.clone())
    }
}

impl<'a> Sha256Verifier<'a, Asn1Signature<NistP256>> for P256Verifier {
    fn verify_sha256(
        &self,
        msg: &'a [u8],
        signature: &Asn1Signature<NistP256>,
    ) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_ASN1,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }
}

impl<'a> Sha256Verifier<'a, FixedSignature<NistP256>> for P256Verifier {
    fn verify_sha256(
        &self,
        msg: &'a [u8],
        signature: &FixedSignature<NistP256>,
    ) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_FIXED,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }
}

/// Generic ECDSA signer which is wrapped with curve and signature-specific types
struct EcdsaSigner<C: WeierstrassCurve, S: EcdsaSignature> {
    /// *ring* ECDSA keypair
    keypair: KeyPair,

    /// Public key for this keypair
    // *ring* does not presently keep a copy of this.
    // See https://github.com/briansmith/ring/issues/672#issuecomment-404669397
    public_key: PublicKey<C>,

    /// Cryptographically secure random number generator
    csrng: SystemRandom,

    /// Signature type produced by this signer
    signature: PhantomData<S>,
}

impl<S> EcdsaSigner<NistP256, S>
where
    S: EcdsaSignature,
{
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(alg: &'static SigningAlgorithm, pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let keypair =
            ring::signature::key_pair_from_pkcs8(alg, untrusted::Input::from(pkcs8_bytes))
                .map_err(|_| err!(KeyInvalid, "invalid PKCS#8 key"))?;

        // TODO: less hokey way of parsing the public key/point from the PKCS#8 file?
        let pk_bytes_pos = pkcs8_bytes
            .len()
            .checked_sub(<NistP256 as WeierstrassCurve>::UntaggedPointSize::to_usize())
            .unwrap();

        let public_key =
            PublicKey::from_untagged_point(&GenericArray::from_slice(&pkcs8_bytes[pk_bytes_pos..]));

        let csrng = SystemRandom::new();

        Ok(Self {
            keypair,
            public_key,
            csrng,
            signature: PhantomData,
        })
    }
}

impl<C, S> EcdsaSigner<C, S>
where
    C: WeierstrassCurve,
    S: EcdsaSignature,
{
    /// Sign a message, returning a *ring* `Signature` type
    fn sign(&self, msg: &[u8]) -> Result<ring::signature::Signature, Error> {
        ring::signature::sign(&self.keypair, &self.csrng, untrusted::Input::from(msg))
            .map_err(|_| err!(ProviderError, "signing failure"))
    }
}

#[cfg(test)]
mod tests {
    use signatory::generic_array::GenericArray;

    use super::{P256Signer, P256Verifier};
    use signatory::{
        self,
        curve::nistp256::{
            Asn1Signature, FixedSignature, PublicKey, SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        encoding::FromPkcs8,
        PublicKeyed, Sha256Verifier, Signature,
    };

    #[test]
    pub fn asn1_signature_roundtrip() {
        // TODO: DER test vectors
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signatory::sign_sha256(&signer, vector.msg).unwrap();

        let verifier = P256Verifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify_sha256(vector.msg, &signature).is_ok());
    }

    #[test]
    pub fn rejects_tweaked_asn1_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signatory::sign_sha256(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = P256Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify_sha256(
            vector.msg,
            &Asn1Signature::from_bytes(tweaked_signature).unwrap(),
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
            let signature: FixedSignature = signatory::sign_sha256(&signer, vector.msg).unwrap();

            let verifier = P256Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify_sha256(vector.msg, &signature).is_ok());

            // Make sure the vector signature verifies
            assert!(
                verifier
                    .verify_sha256(
                        vector.msg,
                        &FixedSignature::from_bytes(&vector.sig).unwrap()
                    )
                    .is_ok()
            );
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: FixedSignature = signatory::sign_sha256(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = P256Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify_sha256(
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

            let fixed_signature: FixedSignature =
                signatory::sign_sha256(&signer, vector.msg).unwrap();

            // Print this out in case it crashes
            println!("fixed signature: {:?}", fixed_signature);

            let asn1_signature = Asn1Signature::from(&fixed_signature);
            let verifier = P256Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify_sha256(vector.msg, &asn1_signature).is_ok());
        }
    }
}
