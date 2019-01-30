//! ECDSA provider for the YubiHSM2 crate (supporting NIST P-256 and secp256k1).
//!
//! To enable secp256k1 support, you need to build `signatory-yubihsm` with the
//! `secp256k1` cargo feature enabled.

#[cfg(feature = "secp256k1")]
use signatory::curve::Secp256k1;
use signatory::{
    curve::{NistP256, NistP384, WeierstrassCurve, WeierstrassCurveKind},
    ecdsa::{Asn1Signature, FixedSignature, PublicKey},
    error::Error,
    generic_array::{
        typenum::{U32, U48},
        GenericArray,
    },
    Digest, DigestSigner, PublicKeyed, Signature,
};
use std::{
    marker::PhantomData,
    sync::{Arc, Mutex},
};
use yubihsm;

use super::{KeyId, Session};

/// ECDSA signature provider for yubihsm-client
pub struct EcdsaSigner<C>
where
    C: WeierstrassCurve,
{
    /// YubiHSM client
    hsm: Arc<Mutex<yubihsm::Client>>,

    /// ID of an ECDSA key to perform signatures with
    signing_key_id: KeyId,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C> EcdsaSigner<C>
where
    C: WeierstrassCurve,
{
    /// Create a new YubiHSM-backed ECDSA signer
    pub(crate) fn create(session: &Session, signing_key_id: KeyId) -> Result<Self, Error> {
        let signer = Self {
            hsm: session.0.clone(),
            signing_key_id,
            curve: PhantomData,
        };

        // Ensure the signing_key_id slot contains a valid ECDSA public key
        signer.public_key()?;

        Ok(signer)
    }

    /// Get the expected `yubihsm::AsymmetricAlg` for this `Curve`
    pub fn asymmetric_alg() -> yubihsm::AsymmetricAlg {
        match C::CURVE_KIND {
            WeierstrassCurveKind::NistP256 => yubihsm::AsymmetricAlg::EC_P256,
            WeierstrassCurveKind::NistP384 => yubihsm::AsymmetricAlg::EC_P384,
            WeierstrassCurveKind::Secp256k1 => yubihsm::AsymmetricAlg::EC_K256,
        }
    }
}

impl<C> PublicKeyed<PublicKey<C>> for EcdsaSigner<C>
where
    C: WeierstrassCurve,
{
    /// Obtain the public key which identifies this signer
    fn public_key(&self) -> Result<PublicKey<C>, Error> {
        let mut hsm = self.hsm.lock().unwrap();

        let pubkey = hsm
            .get_public_key(self.signing_key_id.0)
            .map_err(|e| err!(ProviderError, "{}", e))?;

        if pubkey.algorithm != Self::asymmetric_alg() {
            fail!(
                KeyInvalid,
                "expected a {} key, got: {:?}",
                C::CURVE_KIND.to_str(),
                pubkey.algorithm
            );
        }

        Ok(PublicKey::from_untagged_point(GenericArray::from_slice(
            pubkey.as_ref(),
        )))
    }
}

impl<D> DigestSigner<D, Asn1Signature<NistP256>> for EcdsaSigner<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute an ASN.1 DER-encoded P-256 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<Asn1Signature<NistP256>, Error> {
        self.sign_nistp256_asn1(digest)
    }
}

impl<D> DigestSigner<D, FixedSignature<NistP256>> for EcdsaSigner<NistP256>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-sized P-256 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<FixedSignature<NistP256>, Error> {
        Ok(FixedSignature::from(&self.sign_nistp256_asn1(digest)?))
    }
}

impl<D> DigestSigner<D, Asn1Signature<NistP384>> for EcdsaSigner<NistP384>
where
    D: Digest<OutputSize = U48> + Default,
{
    /// Compute an ASN.1 DER-encoded P-384 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<Asn1Signature<NistP384>, Error> {
        self.sign_nistp384_asn1(digest)
    }
}

impl<D> DigestSigner<D, FixedSignature<NistP384>> for EcdsaSigner<NistP384>
where
    D: Digest<OutputSize = U48> + Default,
{
    /// Compute a fixed-sized P-384 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<FixedSignature<NistP384>, Error> {
        Ok(FixedSignature::from(&self.sign_nistp384_asn1(digest)?))
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, Asn1Signature<Secp256k1>> for EcdsaSigner<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute an ASN.1 DER-encoded secp256k1 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<Asn1Signature<Secp256k1>, Error> {
        let asn1_sig = self.sign_secp256k1(digest)?.serialize_der();

        Ok(Asn1Signature::from_bytes(&asn1_sig).unwrap())
    }
}

#[cfg(feature = "secp256k1")]
impl<D> DigestSigner<D, FixedSignature<Secp256k1>> for EcdsaSigner<Secp256k1>
where
    D: Digest<OutputSize = U32> + Default,
{
    /// Compute a fixed-size secp256k1 ECDSA signature of the given digest
    fn sign(&self, digest: D) -> Result<FixedSignature<Secp256k1>, Error> {
        let fixed_sig =
            GenericArray::clone_from_slice(&self.sign_secp256k1(digest)?.serialize_compact());

        Ok(FixedSignature::from(fixed_sig))
    }
}

impl EcdsaSigner<NistP256> {
    /// Compute an ASN.1 DER signature over P-256
    fn sign_nistp256_asn1<D>(&self, digest: D) -> Result<Asn1Signature<NistP256>, Error>
    where
        D: Digest<OutputSize = U32> + Default,
    {
        let mut hsm = self.hsm.lock().unwrap();

        let signature = hsm
            .sign_ecdsa(self.signing_key_id.0, digest.result().as_slice())
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Asn1Signature::from_bytes(signature)
    }
}

impl EcdsaSigner<NistP384> {
    /// Compute an ASN.1 DER signature over P-384
    fn sign_nistp384_asn1<D>(&self, digest: D) -> Result<Asn1Signature<NistP384>, Error>
    where
        D: Digest<OutputSize = U48> + Default,
    {
        let mut hsm = self.hsm.lock().unwrap();

        let signature = hsm
            .sign_ecdsa(self.signing_key_id.0, digest.result().as_slice())
            .map_err(|e| err!(ProviderError, "{}", e))?;

        Asn1Signature::from_bytes(signature)
    }
}

#[cfg(feature = "secp256k1")]
impl EcdsaSigner<Secp256k1> {
    /// Compute either an ASN.1 DER or fixed-sized signature using libsecp256k1
    fn sign_secp256k1<D>(&self, digest: D) -> Result<secp256k1::Signature, Error>
    where
        D: Digest<OutputSize = U32> + Default,
    {
        let mut hsm = self.hsm.lock().unwrap();

        // Sign the data using the YubiHSM, producing an ASN.1 DER encoded signature
        let raw_sig = hsm
            .sign_ecdsa(self.signing_key_id.0, digest.result().as_slice())
            .map_err(|e| err!(ProviderError, "{}", e))?;

        // Parse the signature using libsecp256k1
        let mut sig = secp256k1::Signature::from_der_lax(raw_sig.as_ref()).unwrap();

        // Normalize the signature to a "low S" form. libsecp256k1 will only
        // accept signatures for which s is in the lower half of the field range.
        // The signatures produced by the YubiHSM do not have this property, so
        // we normalize them to maximize compatibility with secp256k1
        // applications (e.g. Bitcoin).
        sig.normalize_s();

        Ok(sig)
    }
}
