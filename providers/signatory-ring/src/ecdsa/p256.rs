//! ECDSA P-256 provider for the *ring* crate

use ring::{
    self,
    signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
        ECDSA_P256_SHA256_FIXED_SIGNING,
    },
};
use signatory::{
    curve::nistp256::NistP256,
    ecdsa::{Asn1Signature, EcdsaPublicKey, EcdsaSignature, FixedSignature},
    encoding::FromPkcs8,
    error::{Error, ErrorKind::SignatureInvalid},
    PublicKeyed, Sha256Signer, Sha256Verifier,
};
use untrusted;

use super::signer::EcdsaSigner;

/// NIST P-256 ECDSA signer
pub struct P256Signer<S: EcdsaSignature>(EcdsaSigner<NistP256, S>);

impl FromPkcs8 for P256Signer<Asn1Signature<NistP256>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        Ok(P256Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            pkcs8_bytes,
        )?))
    }
}

impl FromPkcs8 for P256Signer<FixedSignature<NistP256>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        Ok(P256Signer(EcdsaSigner::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8_bytes,
        )?))
    }
}

impl<S> PublicKeyed<EcdsaPublicKey<NistP256>> for P256Signer<S>
where
    S: EcdsaSignature + Send + Sync,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<EcdsaPublicKey<NistP256>, Error> {
        Ok(self.0.public_key())
    }
}

impl Sha256Signer<Asn1Signature<NistP256>> for P256Signer<Asn1Signature<NistP256>> {
    fn sign_sha256(&self, msg: &[u8]) -> Result<Asn1Signature<NistP256>, Error> {
        self.0.sign(msg)
    }
}

impl Sha256Signer<FixedSignature<NistP256>> for P256Signer<FixedSignature<NistP256>> {
    fn sign_sha256(&self, msg: &[u8]) -> Result<FixedSignature<NistP256>, Error> {
        self.0.sign(msg)
    }
}

/// NIST P-256 ECDSA verifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P256Verifier(EcdsaPublicKey<NistP256>);

impl<'a> From<&'a EcdsaPublicKey<NistP256>> for P256Verifier {
    fn from(public_key: &'a EcdsaPublicKey<NistP256>) -> Self {
        P256Verifier(public_key.clone())
    }
}

impl Sha256Verifier<Asn1Signature<NistP256>> for P256Verifier {
    fn verify_sha256(&self, msg: &[u8], signature: &Asn1Signature<NistP256>) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_ASN1,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| SignatureInvalid.into())
    }
}

impl Sha256Verifier<FixedSignature<NistP256>> for P256Verifier {
    fn verify_sha256(&self, msg: &[u8], signature: &FixedSignature<NistP256>) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P256_SHA256_FIXED,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| SignatureInvalid.into())
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
                    ).is_ok()
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
