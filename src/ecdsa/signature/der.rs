//! ASN.1 DER-encoded ECDSA signatures

use core::fmt::{self, Debug};
use core::marker::PhantomData;
use generic_array::typenum::Unsigned;
use generic_array::GenericArray;
#[cfg(feature = "std")]
use std::vec::Vec;

use super::fixed::FixedSignature;
use asn1;
use curve::WeierstrassCurve;
use error::Error;
use util::fmt_colon_delimited_hex;

/// ECDSA signatures encoded as ASN.1 DER
#[derive(Clone, PartialEq, Eq)]
pub struct DERSignature<C: WeierstrassCurve> {
    /// Signature data as bytes
    bytes: GenericArray<u8, C::DERSignatureMaxSize>,

    /// Length of the signature in bytes (DER is variable-width)
    length: usize,

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<C: WeierstrassCurve> DERSignature<C> {
    /// Create an ASN.1 DER-encoded ECDSA signature from its serialized byte representation
    pub fn from_bytes<B>(bytes: B) -> Result<Self, Error>
    where
        B: AsRef<[u8]>,
    {
        let length = bytes.as_ref().len();

        // TODO: better validate signature is well-formed ASN.1 DER
        ensure!(
            length <= C::DERSignatureMaxSize::to_usize(),
            SignatureInvalid,
            "max {}-byte signature (got {})",
            C::DERSignatureMaxSize::to_usize(),
            length
        );

        let mut array = GenericArray::default();
        array.as_mut_slice()[..length].copy_from_slice(bytes.as_ref());

        let result = Self {
            bytes: array,
            length,
            curve: PhantomData,
        };

        // Ensure result is well-formed ASN.1 DER
        result.parse()?;

        Ok(result)
    }

    /// Borrow the ASN.1 DER-encoded ECDSA signature as a byte slice
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.length]
    }

    /// Serialize ASN.1 DER-encoded ECDSA signature into a byte vector
    #[cfg(feature = "std")]
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().into()
    }

    /// Parse the ASN.1 DER-encoded ECDSA signature, returning the `r` and `s`
    /// as byte slices.
    fn parse(&self) -> Result<(&[u8], &[u8]), Error> {
        // Signature format is a SEQUENCE of two INTEGER values. We
        // support only integers of less than 127 bytes each (signed
        // encoding) so the resulting raw signature will have length
        // at most 254 bytes.
        let bytes = self.as_bytes();

        // First byte is SEQUENCE tag.
        ensure!(
            bytes[0] == asn1::Type::Sequence.tag(),
            ParseError,
            "ASN.1 error: expected first byte to be a SEQUENCE tag: {}",
            bytes[0]
        );

        // The SEQUENCE length will be encoded over one or two bytes. We
        // limit the total SEQUENCE contents to 255 bytes, because it
        // makes things simpler; this is enough for subgroup orders up
        // to 999 bits.
        let mut seq_len = bytes[1] as usize;

        let mut offset = if seq_len > 0x80 {
            ensure!(
                seq_len == 0x81,
                ParseError,
                "ASN.1 error: overlength signature: {}",
                seq_len
            );

            seq_len = bytes[2] as usize;
            ensure!(
                seq_len == bytes.len().checked_sub(3).unwrap(),
                ParseError,
                "ASN.1 error: sequence length mismatch ({} vs {})",
                seq_len,
                bytes.len().checked_sub(3).unwrap()
            );

            3
        } else {
            ensure!(
                seq_len == bytes.len().checked_sub(2).unwrap(),
                ParseError,
                "ASN.1 error: sequence length mismatch ({} vs {})",
                seq_len,
                bytes.len().checked_sub(2).unwrap()
            );

            2
        };

        // First INTEGER (r)
        ensure!(
            bytes[offset] == asn1::Type::Integer.tag(),
            ParseError,
            "ASN.1 error: expected INTEGER tag (0x02) for 'r' (got 0x{:x})",
            bytes[offset]
        );
        offset = offset.checked_add(1).unwrap();

        let der_r_len = bytes[offset] as usize;
        offset = offset.checked_add(1).unwrap();

        ensure!(
            der_r_len < 0x80,
            ParseError,
            "ASN.1 error: unexpected length for INTEGER 'r': {}",
            der_r_len
        );

        let mut r = &bytes[offset..offset.checked_add(der_r_len).unwrap()];
        offset = offset.checked_add(der_r_len).unwrap();

        // Second INTEGER (s)
        ensure!(
            offset.checked_add(2).unwrap() <= bytes.len(),
            ParseError,
            "ASN.1 error: unexpected length for INTEGER 's': {}",
            bytes.len()
        );

        ensure!(
            bytes[offset] == asn1::Type::Integer.tag(),
            ParseError,
            "ASN.1 error: expected INTEGER tag (0x02) for 's' (got 0x{:x})",
            bytes[offset]
        );

        offset = offset.checked_add(1).unwrap();

        let der_s_len = bytes[offset] as usize;
        offset = offset.checked_add(1).unwrap();

        ensure!(
            der_s_len < 0x80 && der_s_len == bytes.len().checked_sub(offset).unwrap(),
            ParseError,
            "ASN.1 error: unexpected length: {}",
            der_s_len
        );

        let mut s = &bytes[offset..];

        let fixed_int_len = C::FixedSignatureSize::to_usize() >> 1;

        // TODO: handle additional leading zeroes?
        if r.len() > fixed_int_len {
            ensure!(
                r.len() == fixed_int_len.checked_add(1).unwrap(),
                ParseError,
                "ASN.1 error: overlong 'r'"
            );
            ensure!(
                r[0] == 0,
                ParseError,
                "ASN.1 error: expected leading 0 on 'r'"
            );
            r = &r[1..];
        }

        if s.len() > fixed_int_len {
            ensure!(
                s.len() == fixed_int_len.checked_add(1).unwrap(),
                ParseError,
                "ASN.1 error: overlong 's'"
            );
            ensure!(
                s[0] == 0,
                ParseError,
                "ASN.1 error: expected leading 0 on 's'"
            );
            s = &s[1..];
        }

        Ok((r, s))
    }
}

impl<C: WeierstrassCurve> AsRef<[u8]> for DERSignature<C> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<C: WeierstrassCurve> Debug for DERSignature<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "signatory::ecdsa::DERSignature<{:?}>(", C::default())?;
        fmt_colon_delimited_hex(f, self.as_ref())?;
        write!(f, ")")
    }
}

impl<'s, C: WeierstrassCurve> From<&'s FixedSignature<C>> for DERSignature<C> {
    /// Parse `r` and `s` values from a fixed-width signature and reserialize
    /// them as ASN.1 DER.
    fn from(fixed_signature: &FixedSignature<C>) -> Self {
        let fixed_bytes = fixed_signature.as_bytes();
        let mut der_array = GenericArray::default();

        let fixed_sig_len = C::FixedSignatureSize::to_usize();
        let fixed_int_len = fixed_sig_len >> 1;

        // Compute DER-encoded output lengths for the two integers
        let der_r_len = asn1_int_length(&fixed_bytes[..fixed_int_len]);
        let der_s_len = asn1_int_length(&fixed_bytes[fixed_int_len..]);

        assert!(der_r_len <= 125 && der_s_len <= 125, "signature too big");

        let seq_len = der_r_len.checked_add(der_s_len).unwrap();

        let mut der_sig_len = seq_len.checked_add(2).unwrap();

        {
            let der_bytes = der_array.as_mut_slice();

            // SEQUENCE header
            der_bytes[0] = asn1::Type::Sequence.tag();

            let mut der_offset = if seq_len >= 0x80 {
                der_bytes[1] = 0x81;
                der_bytes[2] = seq_len as u8;
                der_sig_len = der_sig_len.checked_add(1).unwrap();
                3usize
            } else {
                der_bytes[1] = seq_len as u8;
                2usize
            };

            // First INTEGER (r)
            let fixed_r_begin = if der_r_len > fixed_int_len {
                0
            } else {
                fixed_int_len.checked_sub(der_r_len).unwrap()
            };

            asn1_int_serialize(
                &mut der_bytes[der_offset..],
                der_r_len,
                &fixed_bytes[fixed_r_begin..fixed_r_begin.checked_add(fixed_int_len).unwrap()],
                fixed_int_len,
            );

            der_offset = der_offset.checked_add(der_r_len).unwrap();

            // Second INTEGER (s)
            let fixed_s_begin = if der_s_len > fixed_int_len {
                fixed_int_len
            } else {
                fixed_sig_len.checked_sub(der_s_len).unwrap()
            };

            asn1_int_serialize(
                &mut der_bytes[der_offset..],
                der_s_len,
                &fixed_bytes[fixed_s_begin..fixed_s_begin.checked_add(fixed_int_len).unwrap()],
                fixed_int_len,
            );
        }

        let result = Self {
            bytes: der_array,
            length: der_sig_len,
            curve: PhantomData,
        };

        // Double-check we produced an ASN.1 signature we can parse ourselves
        #[cfg(debug_assertions)]
        result.parse().unwrap();

        result
    }
}

impl<'s, C: WeierstrassCurve> From<&'s DERSignature<C>> for FixedSignature<C> {
    fn from(der_signature: &DERSignature<C>) -> FixedSignature<C> {
        let mut bytes = GenericArray::default();
        let (r, s) = der_signature.parse().unwrap();

        bytes.as_mut_slice()[..r.len()].copy_from_slice(r);
        bytes.as_mut_slice()[r.len()..].copy_from_slice(s);

        FixedSignature::from(bytes)
    }
}

/// Compute ASN.1 DER encoded length for the provided integer. The ASN.1
/// encoding is signed, so its leading bit must have value 0; it must also be
/// of minimal length (so leading bytes of value 0 must be removed, except if
/// that would contradict the rule about the sign bit).
// TODO: refactor me so I look less like an ugly handrolled C ASN.1 parser
fn asn1_int_length(x: &[u8]) -> usize {
    // Account for the INTEGER tag and length data
    let mut len = x.len().checked_add(2).unwrap();

    // Add extra space for a leading zero
    if x[0] >= 0x80 {
        len = len.checked_add(1).unwrap();
    }

    len
}

/// Serialize an integer as ASN.1 DER. Panics if `der_out` is too small to
/// contain the serialized integer.
// TODO: refactor me so I look less like an ugly handrolled C ASN.1 parser
fn asn1_int_serialize(der_out: &mut [u8], der_len: usize, value: &[u8], h_len: usize) {
    assert!(der_len <= 125, "oversized value");

    der_out[0] = asn1::Type::Integer.tag();
    der_out[1] = der_len.checked_sub(2).unwrap() as u8;

    let mut offset = 2;

    if der_len > h_len.checked_add(offset).unwrap() {
        der_out[2] = 0x00;
        offset = offset.checked_add(1).unwrap();
    }

    der_out[offset..der_len].copy_from_slice(value);
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use curve::nistp256::{DERSignature, FixedSignature, SHA256_FIXED_SIZE_TEST_VECTORS};
    use ecdsa::{
        signer::{SHA256Signer, Signer},
        verifier::SHA256Verifier,
    };
    #[cfg(feature = "ring")]
    use providers::ring::{P256Signer, P256Verifier};

    #[test]
    fn test_fixed_to_der_signature_roundtrip() {
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let fixed_signature = FixedSignature::from_bytes(&vector.sig).unwrap();

            // Convert to DER and back
            let der_signature = DERSignature::from(&fixed_signature);
            let fixed_signature2 = FixedSignature::from(&der_signature);

            assert_eq!(fixed_signature, fixed_signature2);
        }
    }

    #[cfg(feature = "ring")]
    #[test]
    fn test_fixed_to_asn1_transformed_signature_verifies() {
        for vector in SHA256_FIXED_SIZE_TEST_VECTORS {
            let signer = P256Signer::from_pkcs8(&vector.to_pkcs8()).unwrap();
            let public_key = signer.public_key().unwrap();

            let der_signature = DERSignature::from(&signer.sign_sha256_fixed(vector.msg).unwrap());
            P256Verifier::verify_sha256_der_signature(&public_key, vector.msg, &der_signature)
                .unwrap();
        }
    }
}
