//! Impls of `DigestSigner` and `DigestVerifier` for all ECDSA signers and
//! verifiers which accept digest inputs whose size is equal to the curve's
//! modulus (i.e. `ScalarSize` for a particular `WeierstrassCurve`).

use super::{Asn1Signature, FixedSignature};
use curve::WeierstrassCurve;
use digest::Digest;
use signer::{DigestSigner, Signer};
use verifier::{DigestVerifier, Verifier};

impl<C, D, T> DigestSigner<D, Asn1Signature<C>> for T
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::ScalarSize>,
    T: Signer<D, Asn1Signature<C>>,
{
    type DigestSize = C::ScalarSize;
}

impl<C, D, T> DigestSigner<D, FixedSignature<C>> for T
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::ScalarSize>,
    T: Signer<D, FixedSignature<C>>,
{
    type DigestSize = C::ScalarSize;
}

impl<C, D, T> DigestVerifier<D, Asn1Signature<C>> for T
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::ScalarSize>,
    T: Verifier<D, Asn1Signature<C>>,
{
    type DigestSize = C::ScalarSize;
}

impl<C, D, T> DigestVerifier<D, FixedSignature<C>> for T
where
    C: WeierstrassCurve,
    D: Digest<OutputSize = C::ScalarSize>,
    T: Verifier<D, FixedSignature<C>>,
{
    type DigestSize = C::ScalarSize;
}
