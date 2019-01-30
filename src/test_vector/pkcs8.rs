//! Hax PKCS#8 serializers for test vectors

use super::{TestVector, TestVectorAlgorithm};
#[allow(unused_imports)]
use crate::prelude::*;

/// PKCS#8 header for a NIST P-256 private key
const P256_PKCS8_HEADER: &[u8] =
    b"\x30\x81\x87\x02\x01\x00\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\
      \x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20";

/// PKCS#8 interstitial part for a NIST P-256 private key
const P256_PKCS8_PUBKEY_PREFIX: &[u8] = b"\xa1\x44\x03\x42\x00\x04";

/// PKCS#8 header for a NIST P-384 private key
const P384_PKCS8_HEADER: &[u8] =
    b"\x30\x81\xb6\x02\x01\x00\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\
      \x05\x2b\x81\x04\x00\x22\x04\x81\x9e\x30\x81\x9b\x02\x01\x01\x04\x30";

/// PKCS#8 interstitial part for a NIST P-384 private key
const P384_PKCS8_PUBKEY_PREFIX: &[u8] = b"\xa1\x64\x03\x62\x00\x04";

impl TestVector {
    /// Serialize this test vector as a PKCS#8 document
    pub fn to_pkcs8(&self) -> Vec<u8> {
        // TODO: better serializer than giant hardcoded bytestring literals, like a PKCS#8 library,
        // or at least a less bogus internal PKCS#8 implementation
        let mut pkcs8_document = match self.alg {
            TestVectorAlgorithm::NistP256 => P256_PKCS8_HEADER,
            TestVectorAlgorithm::NistP384 => P384_PKCS8_HEADER,
            other => panic!("unsupported test vector algorithm: {:?}", other),
        }
        .to_vec();

        pkcs8_document.extend_from_slice(&self.sk);
        pkcs8_document.extend_from_slice(match self.alg {
            TestVectorAlgorithm::NistP256 => P256_PKCS8_PUBKEY_PREFIX,
            TestVectorAlgorithm::NistP384 => P384_PKCS8_PUBKEY_PREFIX,
            _ => panic!("this shouldn't be!"),
        });
        pkcs8_document.extend_from_slice(&self.pk);

        pkcs8_document
    }
}
