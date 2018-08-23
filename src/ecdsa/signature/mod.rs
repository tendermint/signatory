//! ECDSA signatures

/// ASN.1 DER signatures
pub(crate) mod asn1;

/// Fixed sized signatures
pub(crate) mod fixed;

/// `IntPair`: `r` and `s` integer pair of which ECDSA signatures are comprised
pub(crate) mod pair;

use Signature;

/// Trait for ECDSA signatures
pub trait EcdsaSignature: Signature {
    /// Kind of signature (DER or Fixed)
    const SIGNATURE_KIND: EcdsaSignatureKind;
}

/// Kinds of ECDSA signatures
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum EcdsaSignatureKind {
    /// ASN.1 DER encoded ECDSA signatures
    Asn1,

    /// Fixed-sized (bare concatenated integer) ECDSA signature
    Fixed,
}
