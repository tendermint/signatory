//! Hexadecimal encoder/decoder which avoids data-dependent branching
//! (i.e. constant time-ish)

// Adapted from this C++ implementation:
//
// <https://github.com/Sc00bz/ConstTimeEncoding/blob/master/hex.cpp>
//
// Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use error::Error;

/// Encode hexadecimal (lower case) with branchless / secret-independent logic
pub(super) fn encode(src: &[u8], dst: &mut [u8]) -> usize {
    for (i, src_byte) in src.iter().enumerate() {
        let offset = mul!(i, 2);
        dst[offset] = encode_nibble(shr!(src_byte, 4));
        dst[add!(offset, 1)] = encode_nibble(src_byte & 0x0f);
    }

    mul!(src.len(), 2)
}

/// Decode hexadecimal (upper or lower case) with branchless / secret-independent logic
pub(super) fn decode(src: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
    let src_len = src.len();
    let mut err: usize = 0;

    if src_len == 0 {
        return Ok(0);
    } else if src_len & 1 != 0 {
        fail!(ParseError, "invalid hex encoding (bad length)");
    }

    let dst_len = shr!(src_len, 1);

    if dst_len > dst.len() {
        fail!(ParseError, "input is too long");
    }

    for (i, dst_byte) in dst.iter_mut().enumerate().take(dst_len) {
        let src_offset = mul!(i, 2);
        let byte =
            shl!(decode_nibble(src[src_offset]), 4) | decode_nibble(src[add!(src_offset, 1)]);
        err |= shr!(byte, 8);
        *dst_byte = byte as u8;
    }

    if err == 0 {
        Ok(dst_len)
    } else {
        fail!(ParseError, "error occurred while decoding");
    }
}

/// Decode a single nibble of hex
#[inline]
fn decode_nibble(src: u8) -> usize {
    // 0-9  0x30-0x39
    // A-F  0x41-0x46 or a-f  0x61-0x66
    let mut byte = src as isize;
    let mut ret: isize = -1;

    // if (byte > 0x2f && byte < 0x3a) ret += byte - 0x30 + 1; // -47
    ret = add!(
        ret,
        shr!((sub!(0x2fisize, byte) & sub!(byte, 0x3a)), 8) & sub!(byte, 47)
    );

    // case insensitive decode
    byte |= 0x20;

    // if (byte > 0x60 && byte < 0x67) ret += byte - 0x61 + 10 + 1; // -86
    add!(
        ret,
        shr!(sub!(0x60isize, byte) & sub!(byte, 0x67), 8) & sub!(byte, 86)
    ) as usize
}

/// Encode a single nibble of hex
#[inline]
fn encode_nibble(src: u8) -> u8 {
    let mut ret: isize = src as isize;

    // 0-9  0x30-0x39
    // a-f  0x61-0x66
    ret = add!(ret, 0x30);

    // if (in > 0x39) in += 0x61 - 0x3a;
    add!(ret, shr!(sub!(0x39isize, ret), 8) & sub!(0x61isize, 0x3a)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use error::ErrorKind;

    /// Hexadecimal test vectors
    struct HexVector {
        /// Raw bytes
        raw: &'static [u8],

        /// Hex encoded
        hex: &'static [u8],
    }

    const HEX_TEST_VECTORS: &[HexVector] = &[
        HexVector { raw: b"", hex: b"" },
        HexVector {
            raw: b"\0",
            hex: b"00",
        },
        HexVector {
            raw: b"***",
            hex: b"2a2a2a",
        },
        HexVector {
            raw: b"\x01\x02\x03\x04",
            hex: b"01020304",
        },
        HexVector {
            raw: b"\xAD\xAD\xAD\xAD\xAD",
            hex: b"adadadadad",
        },
        HexVector {
            raw: b"\xFF\xFF\xFF\xFF\xFF",
            hex: b"ffffffffff",
        },
    ];

    #[test]
    fn encode_test_vectors() {
        for vector in HEX_TEST_VECTORS {
            // 10 is the size of the largest encoded test vector
            let mut out = [0u8; 10];
            let out_len = encode(vector.raw, &mut out);
            assert_eq!(vector.hex, &out[..out_len]);
        }
    }

    #[test]
    fn decode_test_vectors() {
        for vector in HEX_TEST_VECTORS {
            // 5 is the size of the largest decoded test vector
            let mut out = [0u8; 5];
            let out_len = decode(vector.hex, &mut out).unwrap();
            assert_eq!(vector.raw, &out[..out_len]);
        }
    }

    #[test]
    fn decode_odd_size_input() {
        let mut out = [0u8; 3];
        assert_eq!(
            decode(b"12345", &mut out).err().unwrap().kind(),
            ErrorKind::ParseError
        )
    }
}
