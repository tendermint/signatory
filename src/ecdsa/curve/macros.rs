//! Macros used for defining elliptic curve types

macro_rules! impl_digest_signature {
    ($digest:ident, $sig_asn1:ident, $sig_fixed:ident) => {
        impl $crate::DigestSignature for $sig_asn1 {
            type Digest = $digest;
        }

        impl $crate::DigestSignature for $sig_fixed {
            type Digest = $digest;
        }
    };
}
