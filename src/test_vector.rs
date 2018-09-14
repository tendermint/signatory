//! Test vector structure for signatures

#[allow(unused_imports)]
use prelude::*;

/// Signature test vector
pub struct TestVector {
    /// Algorithm name
    pub alg: TestVectorAlgorithm,

    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Random nonce value (i.e. ECDSA's `k` value)
    pub nonce: Option<&'static [u8]>,

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],

    /// Expected to pass or fail
    pub pass: bool,
}

impl TestVector {
    /// Serialize this test vector as a PKCS#8 document
    #[cfg(all(feature = "alloc", feature = "test-vectors"))]
    pub fn to_pkcs8(&self) -> Vec<u8> {
        // TODO: support other algorithms besides ECDSA P-256
        if self.alg != TestVectorAlgorithm::NISTP256 {
            panic!("not a NIST P-256 test self: {:?}", self.alg);
        }

        // TODO: better serializer than giant hardcoded bytestring literals, like a PKCS#8 library,
        // or at least a less bogus internal PKCS#8 implementation
        let mut pkcs8_document = b"\x30\x81\x87\x02\x01\x00\x30\x13\
            \x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\
            \x03\x01\x07\x04\x6d\x30\x6b\x02\x01\x01\x04\x20"
            .to_vec();

        pkcs8_document.extend_from_slice(&self.sk);
        pkcs8_document.extend_from_slice(b"\xa1\x44\x03\x42\x00\x04");
        pkcs8_document.extend_from_slice(&self.pk);

        pkcs8_document
    }
}

/// Algorithms for which we have test vectors
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum TestVectorAlgorithm {
    /// NIST P-256 (a.k.a. prime256v1, secp256r1) elliptic curve
    NISTP256,

    /// secp256k1 elliptic curve
    Secp256k1,

    /// "edwards25519" elliptic curve
    Ed25519,
}
