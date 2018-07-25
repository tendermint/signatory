//! ECDSA public keys

use core::fmt;
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;

use super::curve::WeierstrassCurve;
use asn1;
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA public keys
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PublicKey<C: WeierstrassCurve> {
    /// Compressed elliptic curve point representing the public key
    bytes: GenericArray<u8, C::DERPublicKeySize>,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C> PublicKey<C>
where
    C: WeierstrassCurve,
{
    /// Create an ECDSA public key from an ASN.1 DER encoded public key
    /// consisting of a 1-byte DER OCTET STRING tag followed by an elliptic
    /// curve point (compressed or uncompressed) encoded using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0)
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn from_der<B>(der_bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        ensure!(
            der_bytes.as_ref()[0] == Self::asn1_tag() as u8,
            KeyInvalid,
            "public key does not begin with {:?} tag (expected {}, got {})",
            Self::asn1_tag(),
            Self::asn1_tag() as u8,
            der_bytes.as_ref()[0]
        );

        ensure!(
            der_bytes.as_ref().len() == C::DERPublicKeySize::to_usize(),
            KeyInvalid,
            "expected {}-byte DER encoded public key (got {})",
            C::DERPublicKeySize::to_usize(),
            der_bytes.as_ref().len()
        );

        Ok(Self {
            bytes: GenericArray::clone_from_slice(der_bytes.as_ref()),
            curve: PhantomData,
        })
    }

    /// Create an ECDSA public key from its raw encoding in
    /// Octet-String-to-Elliptic-Curve-Point form, sans any DER tag
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let public_key_len = C::DERPublicKeySize::to_usize().checked_sub(1).unwrap();

        ensure!(
            bytes.as_ref().len() == public_key_len,
            KeyInvalid,
            "expected {}-byte fixed-width public key (got {})",
            public_key_len,
            bytes.as_ref().len()
        );

        let mut asn1_der_bytes = GenericArray::default();
        asn1_der_bytes.as_mut_slice()[0] = Self::asn1_tag() as u8;
        asn1_der_bytes.as_mut_slice()[1..].copy_from_slice(bytes.as_ref());

        Ok(Self {
            bytes: asn1_der_bytes,
            curve: PhantomData,
        })
    }

    /// Obtain public key as a byte array reference
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert public key into owned byte array
    #[inline]
    pub fn into_bytes(self) -> GenericArray<u8, C::DERPublicKeySize> {
        self.bytes
    }

    /// Get the expected ASN.1 tag for this elliptic curve's DER-encoded public keys
    // TODO: support both compressed and uncompressed keys?
    #[inline]
    fn asn1_tag() -> asn1::Tag {
        if C::COMPRESSED_PUBLIC_KEY {
            asn1::Tag::BitString
        } else {
            asn1::Tag::OctetString
        }
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for PublicKey<C> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl<C: WeierstrassCurve> fmt::Debug for PublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::PublicKey<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}
