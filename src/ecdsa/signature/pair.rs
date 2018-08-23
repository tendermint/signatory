//! An ECDSA signature comprises 2 integers: `r` and `s`. The integers are
//! the same size as the curve's modulus, i.e. for an elliptic curve based
//! on a ~256-bit prime, they will also be 256-bit (i.e. the same size as
//! `PrivateScalarSize`)
//!
//! The `IntPair` type provides a "view" of these two integers for either
//! ASN.1 DER encoded or fixed-size signatures, and also provides a convenient
//! representation for converting between formats, i.e. all of the serialization
//! code is in this module.

use core::marker::PhantomData;
use generic_array::{typenum::Unsigned, GenericArray};

use super::asn1::Asn1Signature;
use super::fixed::FixedSignature;
use asn1;
use curve::WeierstrassCurve;
use error::Error;
use signature::Signature;

/// ECDSA signature `r` and `s` values
pub(crate) struct IntPair<'a, C: WeierstrassCurve> {
    /// `r` integer value
    // TODO: use a `GenericArray` reference or const generic array reference
    r: &'a [u8],

    /// `s` integer value
    // TODO: use a `GenericArray` reference or const generic array reference
    s: &'a [u8],

    /// Placeholder for elliptic curve type
    curve: PhantomData<C>,
}

impl<'a, C> IntPair<'a, C>
where
    C: WeierstrassCurve,
{
    /// Parse the given ASN.1 DER-encoded ECDSA signature, obtaining the
    /// `r` and `s` integer pair
    pub(crate) fn from_asn1_signature(signature: &'a Asn1Signature<C>) -> Result<Self, Error> {
        // Signature format is a SEQUENCE of two INTEGER values. We
        // support only integers of less than 127 bytes each (signed
        // encoding) so the resulting raw signature will have length
        // at most 254 bytes.
        let bytes = signature.as_slice();

        // First byte is SEQUENCE tag.
        ensure!(
            bytes[0] == asn1::Tag::Sequence as u8,
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
            bytes[offset] == asn1::Tag::Integer as u8,
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
            bytes[offset] == asn1::Tag::Integer as u8,
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

        Ok(Self {
            r,
            s,
            curve: PhantomData,
        })
    }

    /// Parse the given fixed-size ECDSA signature, obtaining the `r` and `s`
    /// integer pair
    pub(crate) fn from_fixed_signature(signature: &'a FixedSignature<C>) -> Self {
        let int_len = Self::fixed_int_length();
        Self {
            r: &signature.as_ref()[..int_len],
            s: &signature.as_ref()[int_len..],
            curve: PhantomData,
        }
    }

    /// Serialize this ECDSA signature's `r` and `s` integer pair as ASN.1 DER
    pub(crate) fn to_asn1_signature(&self) -> Asn1Signature<C> {
        // Compute DER-encoded output lengths for the two integers
        let der_r_len = Self::asn1_int_length(self.r);
        let der_s_len = Self::asn1_int_length(self.s);
        assert!(der_r_len <= 125 && der_s_len <= 125, "signature too big");

        let mut der_array = GenericArray::default();
        let seq_len = der_r_len.checked_add(der_s_len).unwrap();

        let mut der_sig_len = seq_len.checked_add(2).unwrap();

        {
            let der_bytes = der_array.as_mut_slice();

            // SEQUENCE header
            der_bytes[0] = asn1::Tag::Sequence as u8;

            let header_offset = if seq_len >= 0x80 {
                der_bytes[1] = 0x81;
                der_bytes[2] = seq_len as u8;
                der_sig_len = der_sig_len.checked_add(1).unwrap();
                3usize
            } else {
                der_bytes[1] = seq_len as u8;
                2usize
            };

            // First INTEGER (r)
            Self::asn1_int_serialize(self.r, &mut der_bytes[header_offset..], der_r_len);

            // Second INTEGER (s)
            Self::asn1_int_serialize(
                self.s,
                &mut der_bytes[header_offset.checked_add(der_r_len).unwrap()..],
                der_s_len,
            );
        }

        let result = Asn1Signature {
            bytes: der_array,
            length: der_sig_len,
            curve: PhantomData,
        };

        // Double-check we produced an ASN.1 signature we can parse ourselves
        #[cfg(debug_assertions)]
        Self::from_asn1_signature(&result).unwrap();

        result
    }

    pub(crate) fn to_fixed_signature(&self) -> FixedSignature<C> {
        let int_len = Self::fixed_int_length();
        let mut bytes = GenericArray::default();

        bytes.as_mut_slice()[..int_len].copy_from_slice(self.r);
        bytes.as_mut_slice()[int_len..].copy_from_slice(self.s);

        FixedSignature::from(bytes)
    }

    /// Size of an individual integer in the pair for the given curve
    // TODO: replace this with typenum / const generics
    fn fixed_int_length() -> usize {
        C::FixedSignatureSize::to_usize() / 2
    }

    /// Compute ASN.1 DER encoded length for the provided integer. The ASN.1
    /// encoding is signed, so its leading bit must have value 0; it must also be
    /// of minimal length (so leading bytes of value 0 must be removed, except if
    /// that would contradict the rule about the sign bit).
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
    fn asn1_int_serialize(value: &[u8], der_out: &mut [u8], der_len: usize) {
        assert!(der_len <= 125, "oversized value");

        let int_len = Self::fixed_int_length();
        der_out[0] = asn1::Tag::Integer as u8;
        der_out[1] = der_len.checked_sub(2).unwrap() as u8;

        let mut offset = 2;

        if der_len > int_len.checked_add(offset).unwrap() {
            der_out[2] = 0x00;
            offset = offset.checked_add(1).unwrap();
        }

        der_out[offset..der_len].copy_from_slice(value);
    }
}
