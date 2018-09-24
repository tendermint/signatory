//! Base64 encoder/decoder which avoids data-dependent branching
//! (i.e. constant time-ish)

// Adapted from this C++ implementation:
//
// <https://github.com/Sc00bz/ConstTimeEncoding/blob/master/base64.cpp>
//
// Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
// Derived code is dual licensed MIT + Apache 2 (with permission)

use clear_on_drop::clear::Clear;
use error::Error;

/// Encode Base64  with branchless / secret-independent logic.
/// Base64 character set: `[A-Z][a-z][0-9]+/`
pub(crate) fn encode(src: &[u8], dst: &mut [u8]) -> usize {
    let mut src_off: usize = 0;
    let mut dst_off: usize = 0;
    let mut src_len: usize = src.len();

    while src_len >= 3 {
        encode_3bytes(
            &src[src_off..add!(src_off, 3)],
            &mut dst[dst_off..add!(dst_off, 4)],
        );

        src_off = add!(src_off, 3);
        dst_off = add!(dst_off, 4);
        src_len = sub!(src_len, 3);
    }

    if src_len > 0 {
        let mut tmp = [0u8; 3];
        tmp[..src_len].copy_from_slice(&src[src_off..add!(src_off, src_len)]);

        encode_3bytes(&tmp, &mut dst[dst_off..]);
        dst[add!(dst_off, 3)] = b'=';

        if src_len == 1 {
            dst[add!(dst_off, 2)] = b'=';
        }

        dst_off = add!(dst_off, 4);
        tmp.clear();
    }

    dst_off
}

/// Decode Base64 with branchless / secret-independent logic.
/// Base64 character set: `[A-Z][a-z][0-9]+/`
pub(crate) fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let mut src_off: usize = 0;
    let mut dst_off: usize = 0;
    let mut src_len: usize = src.len();
    let mut err: isize = 0;

    while src_len > 4 {
        err |= decode_3bytes(
            &src[src_off..add!(src_off, 4)],
            &mut dst[dst_off..add!(dst_off, 3)],
        );

        src_off = add!(src_off, 4);
        dst_off = add!(dst_off, 3);
        src_len = sub!(src_len, 4);
    }

    if src_len > 0 {
        let mut i = 0;
        let mut tmp_out = [0u8; 3];
        let mut tmp_in = [b'A'; 4];

        while i < src_len && src[add!(src_off, i)] != b'=' {
            tmp_in[i] = src[add!(src_off, i)];
            i = add!(i, 1);
        }

        if i < 2 {
            err = 1;
        }

        src_len = sub!(i, 1);
        err |= decode_3bytes(&tmp_in, &mut tmp_out);

        dst[dst_off..add!(dst_off, src_len)].copy_from_slice(&tmp_out[..src_len]);
        dst_off = add!(dst_off, sub!(i, 1));

        tmp_out.clear();
        tmp_in.clear();
    }

    if err == 0 {
        Ok(dst_off)
    } else {
        fail!(ParseError, "error occurred while decoding");
    }
}

//
// Helper Functions
//

// Base64 character set:
// [A-Z]      [a-z]      [0-9]      +     /
// 0x41-0x5a, 0x61-0x7a, 0x30-0x39, 0x2b, 0x2f

#[inline]
fn encode_3bytes(src: &[u8], dst: &mut [u8]) {
    let b0 = src[0] as isize;
    let b1 = src[1] as isize;
    let b2 = src[2] as isize;

    dst[0] = encode_6bits(shr!(b0, 2));
    dst[1] = encode_6bits((shl!(b0, 4) | shr!(b1, 4)) & 63);
    dst[2] = encode_6bits((shl!(b1, 2) | shr!(b2, 6)) & 63);
    dst[3] = encode_6bits(b2 & 63);
}

#[inline]
fn encode_6bits(src: isize) -> u8 {
    let mut diff: isize = 0x41;

    // if (in > 25) diff += 0x61 - 0x41 - 26; // 6
    diff = add!(diff, shr!(sub!(25isize, src), 8) & 6);

    // if (in > 51) diff += 0x30 - 0x61 - 26; // -75
    diff = sub!(diff, shr!(sub!(51isize, src), 8) & 75);

    // if (in > 61) diff += 0x2b - 0x30 - 10; // -15
    diff = sub!(diff, shr!(sub!(61isize, src), 8) & 15);

    // if (in > 62) diff += 0x2f - 0x2b - 1; // 3
    diff = add!(diff, shr!(sub!(62isize, src), 8) & 3);

    add!(src, diff) as u8
}

#[inline]
fn decode_3bytes(src: &[u8], dst: &mut [u8]) -> isize {
    let c0 = decode_6bits(src[0]);
    let c1 = decode_6bits(src[1]);
    let c2 = decode_6bits(src[2]);
    let c3 = decode_6bits(src[3]);

    dst[0] = (shl!(c0, 2) | shr!(c1, 4)) as u8;
    dst[1] = (shl!(c1, 4) | shr!(c2, 2)) as u8;
    dst[2] = (shl!(c2, 6) | c3) as u8;

    shr!(c0 | c1 | c2 | c3, 8) & 1
}

#[inline]
fn decode_6bits(src: u8) -> isize {
    let ch = src as isize;
    let mut ret: isize = -1;

    // if (ch > 0x40 && ch < 0x5b) ret += ch - 0x41 + 1; // -64
    ret = add!(
        ret,
        shr!(sub!(0x40isize, ch) & sub!(ch, 0x5bisize), 8) & sub!(ch, 64isize)
    );

    // if (ch > 0x60 && ch < 0x7b) ret += ch - 0x61 + 26 + 1; // -70
    ret = add!(
        ret,
        shr!(sub!(0x60isize, ch) & sub!(ch, 0x7bisize), 8) & sub!(ch, 70isize)
    );

    // if (ch > 0x2f && ch < 0x3a) ret += ch - 0x30 + 52 + 1; // 5
    ret = add!(
        ret,
        shr!(sub!(0x2fisize, ch) & sub!(ch, 0x3aisize), 8) & add!(ch, 5isize)
    );

    // if (ch == 0x2b) ret += 62 + 1;
    ret = add!(ret, shr!(sub!(0x2aisize, ch) & sub!(ch, 0x2cisize), 8) & 63);

    // if (ch == 0x2f) ret += 63 + 1;
    add!(ret, shr!(sub!(0x2eisize, ch) & sub!(ch, 0x30isize), 8) & 64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64 test vectors
    struct Base64Vector {
        /// Raw bytes
        raw: &'static [u8],

        /// Hex encoded
        base64: &'static [u8],
    }

    const BASE64_TEST_VECTORS: &[Base64Vector] = &[
        Base64Vector {
            raw: b"",
            base64: b"",
        },
        Base64Vector {
            raw: b"\0",
            base64: b"AA==",
        },
        Base64Vector {
            raw: b"***",
            base64: b"Kioq",
        },
        Base64Vector {
            raw: b"\x01\x02\x03\x04",
            base64: b"AQIDBA==",
        },
        Base64Vector {
            raw: b"\xAD\xAD\xAD\xAD\xAD",
            base64: b"ra2tra0=",
        },
        Base64Vector {
            raw: b"\xFF\xFF\xFF\xFF\xFF",
            base64: b"//////8=",
        },
    ];

    #[test]
    fn encode_test_vectors() {
        for vector in BASE64_TEST_VECTORS {
            // 8 is the size of the largest encoded test vector
            let mut out = [0u8; 8];
            let out_len = encode(vector.raw, &mut out);
            assert_eq!(vector.base64, &out[..out_len]);
        }
    }

    #[test]
    fn decode_test_vectors() {
        for vector in BASE64_TEST_VECTORS {
            // 5 is the size of the largest decoded test vector
            let mut out = [0u8; 5];
            let out_len = decode(vector.base64, &mut out).unwrap();
            assert_eq!(vector.raw, &out[..out_len]);
        }
    }
}
