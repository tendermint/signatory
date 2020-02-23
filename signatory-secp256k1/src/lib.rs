//! ECDSA provider for the `secp256k1` crate (a.k.a. secp256k1-rs)

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/tendermint/signatory/develop/img/signatory-rustacean.png",
    html_root_url = "https://docs.rs/signatory-secp256k1/0.18.0"
)]

pub use signatory;
pub use signatory::ecdsa::curve::secp256k1::{Asn1Signature, FixedSignature, PublicKey, SecretKey};

use secp256k1::{self, Secp256k1, SignOnly, VerifyOnly};
use signatory::{
    public_key::PublicKeyed,
    sha2::Sha256,
    sha3::Keccak256,
    signature::{digest::Digest, DigestSigner, DigestVerifier, Error, Signature, Signer, Verifier},
};

/// ECDSA signature provider for the secp256k1 crate
#[derive(Signer)]
pub struct EcdsaSigner {
    /// ECDSA secret key
    secret_key: secp256k1::SecretKey,

    /// secp256k1 engine
    engine: Secp256k1<SignOnly>,
}

impl From<&SecretKey> for EcdsaSigner {
    /// Create a new secp256k1 signer from the given `SecretKey`
    fn from(secret_key: &SecretKey) -> EcdsaSigner {
        let secret_key =
            secp256k1::SecretKey::from_slice(secret_key.secret_scalar().as_ref()).unwrap();
        let engine = Secp256k1::signing_only();
        EcdsaSigner { secret_key, engine }
    }
}

impl PublicKeyed<PublicKey> for EcdsaSigner {
    /// Return the public key that corresponds to the private key for this signer
    fn public_key(&self) -> Result<PublicKey, Error> {
        let public_key = secp256k1::PublicKey::from_secret_key(&self.engine, &self.secret_key);
        PublicKey::from_bytes(&public_key.serialize()[..]).ok_or_else(Error::new)
    }
}

impl DigestSigner<Sha256, Asn1Signature> for EcdsaSigner {
    /// Compute an ASN.1 DER-encoded signature of the given 32-byte SHA-256 digest
    fn try_sign_digest(&self, digest: Sha256) -> Result<Asn1Signature, Error> {
        Ok(Asn1Signature::from_bytes(self.raw_sign_digest(digest)?.serialize_der()).unwrap())
    }
}

impl DigestSigner<Sha256, FixedSignature> for EcdsaSigner {
    /// Compute a compact, fixed-sized signature of the given 32-byte SHA-256 digest
    fn try_sign_digest(&self, digest: Sha256) -> Result<FixedSignature, Error> {
        Ok(
            FixedSignature::from_bytes(&self.raw_sign_digest(digest)?.serialize_compact()[..])
                .unwrap(),
        )
    }
}

impl DigestSigner<Keccak256, FixedSignature> for EcdsaSigner {
    fn try_sign_digest(&self, digest: Keccak256) -> Result<FixedSignature, Error> {
        Ok(
            FixedSignature::from_bytes(&self.raw_sign_digest(digest)?.serialize_compact()[..])
                .unwrap(),
        )
    }
}

impl EcdsaSigner {
    /// Sign a digest and produce a `secp256k1::Signature`
    fn raw_sign_digest<D: Digest>(&self, digest: D) -> Result<secp256k1::Signature, Error> {
        let msg = secp256k1::Message::from_slice(digest.result().as_slice())
            .map_err(Error::from_source)?;

        Ok(self.engine.sign(&msg, &self.secret_key))
    }
}

/// ECDSA verifier provider for the secp256k1 crate
#[derive(Clone, Debug, Eq, PartialEq, Verifier)]
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

impl DigestVerifier<Sha256, Asn1Signature> for EcdsaVerifier {
    fn verify_digest(&self, digest: Sha256, signature: &Asn1Signature) -> Result<(), Error> {
        self.raw_verify_digest(
            digest,
            secp256k1::Signature::from_der(signature.as_slice()).map_err(Error::from_source)?,
        )
    }
}

impl DigestVerifier<Sha256, FixedSignature> for EcdsaVerifier {
    fn verify_digest(&self, digest: Sha256, signature: &FixedSignature) -> Result<(), Error> {
        self.raw_verify_digest(
            digest,
            secp256k1::Signature::from_compact(signature.as_slice()).map_err(Error::from_source)?,
        )
    }
}

impl EcdsaVerifier {
    /// Verify a digest against a `secp256k1::Signature`
    fn raw_verify_digest(&self, digest: Sha256, sig: secp256k1::Signature) -> Result<(), Error> {
        let msg = secp256k1::Message::from_slice(digest.result().as_slice())
            .map_err(Error::from_source)?;

        self.engine
            .verify(&msg, &sig, &self.public_key)
            .map_err(Error::from_source)
    }
}

// TODO: test against actual test vectors, rather than just checking if signatures roundtrip
#[cfg(test)]
mod tests {
    use super::{EcdsaSigner, EcdsaVerifier, PublicKey, SecretKey};
    use signatory::{
        self,
        ecdsa::{
            curve::secp256k1::{Asn1Signature, FixedSignature},
            test_vectors::secp256k1::SHA256_FIXED_SIZE_TEST_VECTORS,
        },
        public_key::PublicKeyed,
        signature::{Signature, Signer, Verifier},
    };

    #[test]
    pub fn asn1_signature_roundtrip() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];
        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());

        let signature: Asn1Signature = signer.sign(vector.msg);

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
        assert!(verifier.verify(vector.msg, &signature).is_ok());
    }

    #[test]
    pub fn rejects_tweaked_asn1_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];
        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());

        let signature: Asn1Signature = signer.sign(vector.msg);
        let mut tweaked_signature = signature.as_ref().to_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
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
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());
            let public_key = PublicKey::from_bytes(vector.pk).unwrap();
            assert_eq!(signer.public_key().unwrap(), public_key);

            let signature: FixedSignature = signer.sign(vector.msg);
            assert_eq!(signature.as_ref(), vector.sig);

            EcdsaVerifier::from(&public_key)
                .verify(vector.msg, &signature)
                .unwrap();
        }
    }

    #[test]
    pub fn rejects_tweaked_fixed_signature() {
        let vector = &SHA256_FIXED_SIZE_TEST_VECTORS[0];
        let signer = EcdsaSigner::from(&SecretKey::from_bytes(vector.sk).unwrap());

        let signature: FixedSignature = signer.sign(vector.msg);
        let mut tweaked_signature = signature.as_ref().to_vec();
        *tweaked_signature.iter_mut().last().unwrap() ^= 42;

        let verifier = EcdsaVerifier::from(&signer.public_key().unwrap());
        let result = verifier.verify(
            vector.msg,
            &FixedSignature::from_bytes(tweaked_signature).unwrap(),
        );

        assert!(
            result.is_err(),
            "expected bad signature to cause validation error!"
        );
    }
}
