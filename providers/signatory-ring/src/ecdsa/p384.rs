//! ECDSA P-384 provider for the *ring* crate

use ring::{
    self,
    signature::{
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P384_SHA384_FIXED,
        ECDSA_P384_SHA384_FIXED_SIGNING,
    },
};
use signatory::{
    curve::{nistp384::NistP384, WeierstrassCurve},
    ecdsa::{Asn1Signature, EcdsaPublicKey, EcdsaSignature, FixedSignature},
    encoding::FromPkcs8,
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    PublicKeyed, Sha384Signer, Sha384Verifier, Signature,
};
use untrusted;

use super::signer::EcdsaSigner;

/// NIST P-384 ECDSA signer
pub struct P384Signer<S: EcdsaSignature> {
    /// P-384 signer
    signer: EcdsaSigner<S>,

    /// Public key for this signer
    // *ring* does not presently keep a copy of this.
    // See https://github.com/briansmith/ring/issues/672#issuecomment-404669397
    public_key: EcdsaPublicKey<NistP384>,
}

impl FromPkcs8 for P384Signer<Asn1Signature<NistP384>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let signer = EcdsaSigner::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes)?;
        let public_key = p384_pkcs8_pubkey(pkcs8_bytes);
        Ok(P384Signer { signer, public_key })
    }
}

impl FromPkcs8 for P384Signer<FixedSignature<NistP384>> {
    /// Create a new ECDSA signer which produces fixed-width signatures from a PKCS#8 keypair
    fn from_pkcs8(pkcs8_bytes: &[u8]) -> Result<Self, Error> {
        let signer = EcdsaSigner::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8_bytes)?;
        let public_key = p384_pkcs8_pubkey(pkcs8_bytes);
        Ok(P384Signer { signer, public_key })
    }
}

impl<S> PublicKeyed<EcdsaPublicKey<NistP384>> for P384Signer<S>
where
    S: EcdsaSignature + Send + Sync,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<EcdsaPublicKey<NistP384>, Error> {
        Ok(self.public_key.clone())
    }
}

impl Sha384Signer<Asn1Signature<NistP384>> for P384Signer<Asn1Signature<NistP384>> {
    fn sign_sha384(&self, msg: &[u8]) -> Result<Asn1Signature<NistP384>, Error> {
        Asn1Signature::from_bytes(self.signer.sign(msg)?)
    }
}

impl Sha384Signer<FixedSignature<NistP384>> for P384Signer<FixedSignature<NistP384>> {
    fn sign_sha384(&self, msg: &[u8]) -> Result<FixedSignature<NistP384>, Error> {
        FixedSignature::from_bytes(self.signer.sign(msg)?)
    }
}

/// NIST P-384 ECDSA verifier
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P384Verifier(EcdsaPublicKey<NistP384>);

impl<'a> From<&'a EcdsaPublicKey<NistP384>> for P384Verifier {
    fn from(public_key: &'a EcdsaPublicKey<NistP384>) -> Self {
        P384Verifier(public_key.clone())
    }
}

impl Sha384Verifier<Asn1Signature<NistP384>> for P384Verifier {
    fn verify_sha384(&self, msg: &[u8], signature: &Asn1Signature<NistP384>) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P384_SHA384_ASN1,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }
}

impl Sha384Verifier<FixedSignature<NistP384>> for P384Verifier {
    fn verify_sha384(&self, msg: &[u8], signature: &FixedSignature<NistP384>) -> Result<(), Error> {
        ring::signature::verify(
            &ECDSA_P384_SHA384_FIXED,
            untrusted::Input::from(self.0.as_ref()),
            untrusted::Input::from(msg),
            untrusted::Input::from(signature.as_ref()),
        ).map_err(|_| err!(SignatureInvalid, "invalid signature"))
    }
}

/// Get the public key for a P-384 keypair from a PKCS#8 document
fn p384_pkcs8_pubkey(pkcs8_bytes: &[u8]) -> EcdsaPublicKey<NistP384> {
    // TODO: less hokey way of parsing the public key/point from the PKCS#8 file?
    let pk_bytes_pos = pkcs8_bytes
        .len()
        .checked_sub(<NistP384 as WeierstrassCurve>::UntaggedPointSize::to_usize())
        .unwrap();

    EcdsaPublicKey::from_untagged_point(&GenericArray::from_slice(&pkcs8_bytes[pk_bytes_pos..]))
}

#[cfg(test)]
mod tests {
    use signatory::generic_array::GenericArray;

    use super::{P384Signer, P384Verifier};
    use signatory::{
        self,
        curve::nistp384::{
            Asn1Signature, FixedSignature, PublicKey, SHA384_FIXED_SIZE_TEST_VECTORS,
        },
        encoding::FromPkcs8,
        PublicKeyed, Sha384Verifier, Signature,
    };

    #[test]
    pub fn asn1_signature_roundtrip() {
        // TODO: DER test vectors
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P384Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signatory::sign_sha384(&signer, vector.msg).unwrap();

        let verifier = P384Verifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify_sha384(vector.msg, &signature).is_ok());
    }

    #[test]
    pub fn rejects_tweaked_asn1_signature() {
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P384Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: Asn1Signature = signatory::sign_sha384(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = P384Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify_sha384(
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
            let signer = P384Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();

            // Make sure we compute the vector's public key
            let public_key = PublicKey::from_untagged_point(&GenericArray::from_slice(vector.pk));

            assert_eq!(signer.public_key().unwrap(), public_key);

            // Compute a signature with a random `k`
            // TODO: test deterministic `k`
            let signature: FixedSignature = signatory::sign_sha384(&signer, vector.msg).unwrap();

            let verifier = P384Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify_sha384(vector.msg, &signature).is_ok());

            // Make sure the vector signature verifies
            assert!(
                verifier
                    .verify_sha384(
                        vector.msg,
                        &FixedSignature::from_bytes(&vector.sig).unwrap()
                    ).is_ok()
            );
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA384_FIXED_SIZE_TEST_VECTORS[0];

        let signer = P384Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
        let signature: FixedSignature = signatory::sign_sha384(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_bytes();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = P384Verifier::from(&signer.public_key().unwrap());
        let result = verifier.verify_sha384(
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
            let signer = P384Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();

            let fixed_signature: FixedSignature =
                signatory::sign_sha384(&signer, vector.msg).unwrap();

            // Print this out in case it crashes
            println!("fixed signature: {:?}", fixed_signature);

            let asn1_signature = Asn1Signature::from(&fixed_signature);
            let verifier = P384Verifier::from(&signer.public_key().unwrap());
            assert!(verifier.verify_sha384(vector.msg, &asn1_signature).is_ok());
        }
    }
}
