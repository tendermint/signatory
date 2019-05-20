//! ECDSA provider for the `secp256k1` crate (a.k.a. secp256k1-rs)

#![deny(warnings, missing_docs, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-secp256k1/0.11.0"
)]

use secp256k1::{self, Secp256k1, SignOnly, VerifyOnly};
use signatory::{
    digest::Digest,
    ecdsa::curve::secp256k1::{Asn1Signature, FixedSignature, PublicKey, SecretKey},
    error::ErrorKind::SignatureInvalid,
    generic_array::typenum::U32,
    DigestSigner, DigestVerifier, Error, PublicKeyed, Signature,
};

/// ECDSA signature provider for the secp256k1 crate
pub struct EcdsaSigner {
    /// ECDSA secret key
    secret_key: secp256k1::SecretKey,

    /// secp256k1 engine
    engine: Secp256k1<SignOnly>,
}

impl<'a> From<&'a SecretKey> for EcdsaSigner {
    /// Create a new secp256k1 signer from the given `SecretKey`
    fn from(secret_key: &'a SecretKey) -> EcdsaSigner {
        let secret_key = secp256k1::SecretKey::from_slice(secret_key.as_secret_slice()).unwrap();
        let engine = Secp256k1::signing_only();

        EcdsaSigner { secret_key, engine }
    }
}

impl PublicKeyed<PublicKey> for EcdsaSigner {
    /// Return the public key that corresponds to the private key for this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let public_key = secp256k1::PublicKey::from_secret_key(&self.engine, &self.secret_key);
        PublicKey::from_bytes(&public_key.serialize()[..])
    }
}

impl<D> DigestSigner<D, Asn1Signature> for EcdsaSigner
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute an ASN.1 DER-encoded signature of the given 32-byte SHA-256 digest
    fn sign(&self, digest: D) -> Result<Asn1Signature, Error> {
        let msg = secp256k1::Message::from_slice(digest.result().as_slice()).unwrap();
        let sig = self.engine.sign(&msg, &self.secret_key);
        Ok(Asn1Signature::from_bytes(sig.serialize_der()).unwrap())
    }
}

impl<D> DigestSigner<D, FixedSignature> for EcdsaSigner
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a compact, fixed-sized signature of the given 32-byte SHA-256 digest
    fn sign(&self, digest: D) -> Result<FixedSignature, Error> {
        let msg = secp256k1::Message::from_slice(digest.result().as_slice()).unwrap();
        let sig = self.engine.sign(&msg, &self.secret_key);
        Ok(FixedSignature::from_bytes(&sig.serialize_compact()[..]).unwrap())
    }
}

/// ECDSA verifier provider for the secp256k1 crate
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcdsaVerifier {
    /// ECDSA public key
    public_key: secp256k1::PublicKey,

    /// ECDSA engine
    engine: Secp256k1<VerifyOnly>,
}

impl<'a> From<&'a PublicKey> for EcdsaVerifier {
    fn from(public_key: &'a PublicKey) -> Self {
        let public_key = secp256k1::PublicKey::from_slice(public_key.as_bytes()).unwrap();
        let engine = Secp256k1::verification_only();

        EcdsaVerifier { public_key, engine }
    }
}

impl<D> DigestVerifier<D, Asn1Signature> for EcdsaVerifier
where
    D: Digest<OutputSize = U32> + Default,
{
    fn verify(&self, digest: D, signature: &Asn1Signature) -> Result<(), Error> {
        let sig = secp256k1::Signature::from_der(signature.as_slice())
            .map_err(|_| Error::from(SignatureInvalid))?;

        self.engine
            .verify(
                &secp256k1::Message::from_slice(digest.result().as_slice()).unwrap(),
                &sig,
                &self.public_key,
            )
            .map_err(|_| Error::from(SignatureInvalid))?;

        Ok(())
    }
}

impl<D> DigestVerifier<D, FixedSignature> for EcdsaVerifier
where
    D: Digest<OutputSize = U32> + Default,
{
    fn verify(&self, digest: D, signature: &FixedSignature) -> Result<(), Error> {
        let sig = secp256k1::Signature::from_compact(signature.as_slice()).unwrap();

        self.engine
            .verify(
                &secp256k1::Message::from_slice(digest.result().as_slice()).unwrap(),
                &sig,
                &self.public_key,
            )
            .map_err(|_| SignatureInvalid.into())
    }
}

// TODO: test against actual test vectors, rather than just checking if signatures roundtrip
#[cfg(test)]
mod tests {
    use super::{EcdsaSigner, EcdsaVerifier};
    use signatory::{
        self,
        ecdsa::curve::secp256k1::{
            Asn1Signature, FixedSignature, PublicKey, SecretKey, SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        PublicKeyed, Sha256Verifier, Signature,
    };

    #[test]
    pub fn asn1_signature_roundtrip() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());
        let signature: Asn1Signature = signatory::sign_sha256(&signer, vector.msg).unwrap();

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify_sha256(vector.msg, &signature).is_ok());
    }

    #[test]
    pub fn rejects_tweaked_asn1_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());
        let signature: Asn1Signature = signatory::sign_sha256(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
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
            let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());
            let public_key = PublicKey::from_bytes(vector.pk).unwrap();
            assert_eq!(signer.public_key().unwrap(), public_key);

            let signature: FixedSignature = signatory::sign_sha256(&signer, vector.msg).unwrap();
            assert_eq!(signature.as_ref(), vector.sig);

            EcdsaVerifier::from(&public_key)
                .verify_sha256(vector.msg, &signature)
                .unwrap();
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];

        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());
        let signature: FixedSignature = signatory::sign_sha256(&signer, vector.msg).unwrap();
        let mut tweaked_signature = signature.into_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
        let result = verifier.verify_sha256(
            vector.msg,
            &FixedSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }
}
