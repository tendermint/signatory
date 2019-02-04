//! ECDSA P-256 provider for the *ring* crate

use ring::{
    self,
    rand::SystemRandom,
    signature::{
        EcdsaKeyPair, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING,
    },
};
use signatory::{
    ecdsa::{self, curve::nistp256},
    encoding::pkcs8::{self, FromPkcs8, GeneratePkcs8},
    error::{Error, ErrorKind::SignatureInvalid},
    PublicKeyed, Sha256Signer, Sha256Verifier,
};
use untrusted;

use super::signer::EcdsaSigner;

/// NIST P-256 ECDSA signer
pub struct P256Signer<S>(EcdsaSigner<S>)
where
    S: ecdsa::Signature;

impl FromPkcs8 for P256Signer<nistp256::Asn1Signature> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, Error> {
        Ok(P256Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            secret_key.as_ref(),
        )?))
    }
}

impl FromPkcs8 for P256Signer<nistp256::FixedSignature> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8<K: AsRef<[u8]>>(secret_key: K) -> Result<Self, Error> {
        Ok(P256Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            secret_key.as_ref(),
        )?))
    }
}

impl GeneratePkcs8 for P256Signer<nistp256::Asn1Signature> {
    /// Randomly generate a P-256 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, Error> {
        let keypair =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
                .unwrap();

        pkcs8::SecretKey::from_bytes(keypair.as_ref())
    }
}

impl GeneratePkcs8 for P256Signer<nistp256::FixedSignature> {
    /// Randomly generate a P-256 **PKCS#8** keypair
    fn generate_pkcs8() -> Result<pkcs8::SecretKey, Error> {
        let keypair =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();

        pkcs8::SecretKey::from_bytes(keypair.as_ref())
    }
}

impl<S> PublicKeyed<nistp256::PublicKey> for P256Signer<S>
where
    S: ecdsa::Signature + Send + Sync,
{
    fn public_key(&self) -> Result<nistp256::PublicKey, Error> {
        nistp256::PublicKey::from_bytes(self.0.public_key())
    }
}

impl Sha256Signer<nistp256::Asn1Signature> for P256Signer<nistp256::Asn1Signature> {
    fn sign_sha256(&self, msg: &[u8]) -> Result<nistp256::Asn1Signature, Error> {
        self.0.sign(msg)
    }
}

impl Sha256Signer<nistp256::FixedSignature> for P256Signer<nistp256::FixedSignature> {
    fn sign_sha256(&self, msg: &[u8]) -> Result<nistp256::FixedSignature, Error> {
        self.0.sign(msg)
    }
}

/// NIST P-256 ECDSA verifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P256Verifier(nistp256::PublicKey);

impl<'a> From<&'a nistp256::PublicKey> for P256Verifier {
    fn from(public_key: &'a nistp256::PublicKey) -> Self {
        P256Verifier(public_key.clone())
    }
}

impl Sha256Verifier<nistp256::Asn1Signature> for P256Verifier {
    fn verify_sha256(&self, msg: &[u8], signature: &nistp256::Asn1Signature) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_ASN1,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        )
        .map_err(|_| SignatureInvalid.into())
    }
}

impl Sha256Verifier<nistp256::FixedSignature> for P256Verifier {
    fn verify_sha256(&self, msg: &[u8], signature: &nistp256::FixedSignature) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_FIXED,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        )
        .map_err(|_| SignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use signatory::generic_array::GenericArray;

    use super::{P256Signer, P256Verifier};
    use signatory::{
        self,
        ecdsa::curve::nistp256::{
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
            assert!(verifier
                .verify_sha256(
                    vector.msg,
                    &FixedSignature::from_bytes(&vector.sig).unwrap()
                )
                .is_ok());
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

            let asn1_signature = Asn1Signature::from(&fixed_signature);
            let verifier = P256Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify_sha256(vector.msg, &asn1_signature).is_ok());
        }
    }

    /// Ensure leading zeros are handled properly when serializing ASN.1 signatures
    #[test]
    fn test_fixed_to_asn1_leading_zero_handling() {
        // Failing case is a signature using a key/msg from test vector
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[1];

        let fixed_signature = FixedSignature::from_bytes(
            b"\xd1\x64\xfd\xe7\x8d\xd5\x3d\xb8\xb3\xc7\x88\x3d\x40\x8a\x79\x28\
            \x17\x70\x5b\x73\x6b\xc9\x97\x47\xba\x7c\x50\x48\x0b\x6f\x84\x54\
            \x00\x06\x9d\x3a\x33\x6b\x40\xc0\x83\x83\x36\x2e\xe5\x8c\x46\x71\
            \x7e\x22\x30\x1e\xd9\x98\xb6\xcc\xaa\x43\x35\x7f\x97\x56\xe2\x5c"
                .as_ref(),
        )
        .unwrap();

        let public_key = PublicKey::from_untagged_point(&GenericArray::from_slice(vector.pk));
        let verifier = P256Verifier::from(&public_key);
        assert!(verifier.verify_sha256(vector.msg, &fixed_signature).is_ok());

        let asn1_signature = Asn1Signature::from(&fixed_signature);
        assert!(verifier.verify_sha256(vector.msg, &asn1_signature).is_ok());
    }
}
