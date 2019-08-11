//! ECDSA P-384 provider for the *ring* crate

pub use signatory::ecdsa::curve::nistp384::{Asn1Signature, FixedSignature, PublicKey};

use ring::{
    rand::SystemRandom,
    signature::{
        UnparsedPublicKey, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
        ECDSA_P384_SHA384_FIXED, ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};
use signatory::{
    ecdsa,
    encoding::{
        self,
        pkcs8::{self, FromPkcs8, GeneratePkcs8},
    },
    public_key::PublicKeyed,
    signature,
};

use super::signer::EcdsaSigner;

/// NIST P-384 ECDSA signer
pub struct Signer<S>(EcdsaSigner<S>)
where
    S: ecdsa::Signature;

impl FromPkcs8 for Signer<Asn1Signature> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, encoding::Error> {
        Ok(Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            secret_key.as_ref(),
        )?))
    }
}

impl FromPkcs8 for Signer<FixedSignature> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, encoding::Error> {
        Ok(Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            secret_key.as_ref(),
        )?))
    }
}

impl GeneratePkcs8 for Signer<Asn1Signature> {
    /// Randomly generate a P-384 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, encoding::Error> {
        let keypair = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            &SystemRandom::new(),
        )
        .unwrap();
        pkcs8::SecretKey::from_bytes(keypair.as_ref())
    }
}

impl GeneratePkcs8 for Signer<FixedSignature> {
    /// Randomly generate a P-384 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, encoding::Error> {
        let keypair = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            &SystemRandom::new(),
        )
        .unwrap();
        pkcs8::SecretKey::from_bytes(keypair.as_ref())
    }
}

impl<S> PublicKeyed<PublicKey> for Signer<S>
where
    S: ecdsa::Signature + Send + Sync,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey, signature::Error> {
        PublicKey::from_bytes(self.0.public_key()).ok_or_else(signature::Error::new)
    }
}

impl signature::Signer<Asn1Signature> for Signer<Asn1Signature> {
    fn try_sign(&self, msg: &[u8]) -> Result<Asn1Signature, signature::Error> {
        self.0.sign(msg)
    }
}

impl signature::Signer<FixedSignature> for Signer<FixedSignature> {
    fn try_sign(&self, msg: &[u8]) -> Result<FixedSignature, signature::Error> {
        self.0.sign(msg)
    }
}

/// NIST P-384 ECDSA verifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verifier(PublicKey);

impl<'a> From<&'a PublicKey> for Verifier {
    fn from(public_key: &'a PublicKey) -> Self {
        Verifier(*public_key)
    }
}

impl signature::Verifier<Asn1Signature> for Verifier {
    fn verify(&self, msg: &[u8], signature: &Asn1Signature) -> Result<(), signature::Error> {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, self.0.as_ref())
            .verify(msg, signature.as_ref())
            .map_err(|_| signature::Error::new())
    }
}

impl signature::Verifier<FixedSignature> for Verifier {
    fn verify(&self, msg: &[u8], signature: &FixedSignature) -> Result<(), signature::Error> {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, self.0.as_ref())
            .verify(msg, signature.as_ref())
            .map_err(|_| signature::Error::new())
    }
}

#[cfg(test)]
mod tests {
    use super::{Signer, Verifier};
    use signatory::{
        ecdsa::curve::nistp384::{
            Asn1Signature, FixedSignature, PublicKey, SHA384_FIXED_SIZE_TEST_VECTORS,
        },
        encoding::FromPkcs8,
        generic_array::GenericArray,
        public_key::PublicKeyed,
        signature::{Signature as _, Signer as _, Verifier as _},
    };

    #[test]
    pub fn asn1_signature_roundtrip() {
        // TODO: DER test vectors
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];

        let signer = Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signer.sign(vector.msg);

        let verifier = Verifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify(vector.msg, &signature).is_ok());
    }

    #[test]
    pub fn rejects_tweaked_asn1_signature() {
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];
        let signer = Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signer.sign(vector.msg);

        let mut tweaked_signature = signature.into_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify(
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
        for vector in SHA384_FIXED_SIZE_TEST_VECTORS {
            let signer = Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
            let public_key = PublicKey::from_untagged_point(&GenericArray::from_slice(vector.pk));
            assert_eq!(signer.public_key().unwrap(), public_key);

            // Compute a signature with a random `k`
            // TODO: test deterministic `k`
            let signature: FixedSignature = signer.sign(vector.msg);

            let verifier = Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify(vector.msg, &signature).is_ok());

            // Make sure the vector signature verifies
            assert!(verifier
                .verify(
                    vector.msg,
                    &FixedSignature::from_bytes(&vector.sig).unwrap()
                )
                .is_ok());
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];
        let signer = Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: FixedSignature = signer.sign(vector.msg);

        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify(
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
        for vector in SHA384_FIXED_SIZE_TEST_VECTORS {
            let signer = Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
            let fixed_signature: FixedSignature = signer.sign(vector.msg);

            let asn1_signature = Asn1Signature::from(&fixed_signature);
            let verifier = Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify(vector.msg, &asn1_signature).is_ok());
        }
    }
}
